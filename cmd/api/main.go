// Command API exposes user authentication HTTP API.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-redis/redis"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/oklog/run"
	"github.com/oklog/ulid"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/fmitra/authenticator/internal/deviceapi"
	"github.com/fmitra/authenticator/internal/loginapi"
	"github.com/fmitra/authenticator/internal/otp"
	"github.com/fmitra/authenticator/internal/password"
	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/signupapi"
	"github.com/fmitra/authenticator/internal/test"
	"github.com/fmitra/authenticator/internal/token"
	"github.com/fmitra/authenticator/internal/webauthn"
)

func main() {
	var err error

	var logger log.Logger
	{
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	var configPath string
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	{
		fs.Bool("api.debug", false, "Enable debug logging")
		fs.String("api.http-addr", ":8080", "Address to listen on")
		fs.String("api.allowed-origins", "*", "Comma separated list of allowed origins")
		fs.String("api.cookie-domain", "", "Domain to set HTTP cookie")
		fs.Int("api.cookie-max-age", 605800, "Max age of cookie, in seconds")
		fs.String("pg.conn-string", "", "Postgres connection string")
		fs.String("redis.conn-string", "", "Redis connection string")
		fs.Int("password.min-length", 8, "Minimum password length")
		fs.Int("password.max-length", 1000, "Maximum password length")
		fs.Int("otp.code-length", 6, "OTP code length")
		fs.Duration("token.expires-in", time.Minute*20, "JWT token expiry time")
		fs.String("token.issuer", "authenticator", "JWT token issuer")
		fs.String("token.secret", "", "JWT token secret")
		fs.String("webauthn.display-name", "Authenticator", "Webauthn display name")
		fs.String("webauthn.domain", "authenticator.local", "Public client domain")
		fs.String("webauthn.request-origin", "authenticator.local", "Origin URL for client requests")

		fs.StringVar(&configPath, "config", "", "Path to the config file")
		err = fs.Parse(os.Args[1:])
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		if err != nil {
			logger.Log("msg", "failed to parse cli flags", "err", err)
			os.Exit(1)
		}
	}

	if _, err = os.Stat(configPath); !os.IsNotExist(err) {
		viper.SetConfigFile(configPath)
		err = viper.ReadInConfig()
		if err != nil {
			logger.Log("msg", "failed to load config file", "err", err)
			os.Exit(1)
		}
	}
	if err = viper.BindPFlags(fs); err != nil {
		logger.Log("msg", "failed to load cli flags", "err", err)
		os.Exit(1)
	}

	if viper.GetBool("api.debug") {
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	var entropy io.Reader
	{
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		entropy = ulid.Monotonic(random, 0)
	}

	passwordSvc := password.NewPassword(
		password.WithMinLength(viper.GetInt("password.min-length")),
		password.WithMaxLength(viper.GetInt("password.max-length")),
	)

	var pgDB *sql.DB
	{
		pgDB, err = sql.Open("postgres", viper.GetString("pg.conn-string"))
		if err != nil {
			logger.Log("msg", "postgres connection failed", "err", err)
			os.Exit(1)
		}
		if err = pgDB.Ping(); err != nil {
			logger.Log("msg", "postgres did not respond", "err", err)
			os.Exit(1)
		}
		defer func() {
			if err = pgDB.Close(); err != nil {
				logger.Log("msg", "failed to close postgres connection", "err", err)
			}
		}()
	}

	var redisDB *redis.Client
	{
		redisConf, err := redis.ParseURL(viper.GetString("redis.conn-string"))
		if err != nil {
			logger.Log("msg", "invalid redis configuration", "err", err)
			os.Exit(1)
		}
		redisDB = redis.NewClient(redisConf)
		closeRedis := func() {
			if err = redisDB.Close(); err != nil {
				logger.Log("msg", "failed to close redis connection", "err", err)
			}
		}

		if _, err = redisDB.Ping().Result(); err != nil {
			logger.Log("msg", "redis connection failed", "err", err)
			closeRedis()
			os.Exit(1)
		}
		defer closeRedis()
	}

	repoMngr := pg.NewClient(
		pg.WithLogger(logger),
		pg.WithEntropy(entropy),
		pg.WithPassword(passwordSvc),
		pg.WithDB(pgDB),
	)

	otpSvc := otp.NewOTP(
		otp.WithCodeLength(viper.GetInt("otp.code-length")),
	)

	tokenSvc := token.NewService(
		token.WithLogger(logger),
		token.WithDB(redisDB),
		token.WithTokenExpiry(viper.GetDuration("token.expires-in")),
		token.WithEntropy(entropy),
		token.WithIssuer(viper.GetString("token.issuer")),
		token.WithSecret(viper.GetString("token.secret")),
		token.WithOTP(otpSvc),
		token.WithCookieMaxAge(viper.GetInt("api.cookie-max-age")),
		token.WithCookieDomain(viper.GetString("api.cookie-domain")),
	)

	webauthnSvc, err := webauthn.NewService(
		webauthn.WithDB(redisDB),
		webauthn.WithDisplayName(viper.GetString("webauthn.display-name")),
		webauthn.WithDomain(viper.GetString("webauthn.domain")),
		webauthn.WithRequestOrigin(viper.GetString("webauthn.request-origin")),
		webauthn.WithRepoManager(repoMngr),
	)
	if err != nil {
		logger.Log("msg", "failed to build webauthn service", "err", err)
		os.Exit(1)
	}

	loginAPI := loginapi.NewService(
		loginapi.WithLogger(logger),
		loginapi.WithTokenService(tokenSvc),
		loginapi.WithRepoManager(repoMngr),
		loginapi.WithWebAuthn(webauthnSvc),
		loginapi.WithOTP(otpSvc),
		loginapi.WithMessaging(&test.MessagingService{}),
		loginapi.WithPassword(passwordSvc),
	)

	signupAPI := signupapi.NewService(
		signupapi.WithLogger(logger),
		signupapi.WithTokenService(tokenSvc),
		signupapi.WithRepoManager(repoMngr),
		signupapi.WithMessaging(&test.MessagingService{}),
		signupapi.WithOTP(otpSvc),
	)

	deviceAPI := deviceapi.NewService(
		deviceapi.WithLogger(logger),
		deviceapi.WithWebAuthn(webauthnSvc),
		deviceapi.WithRepoManager(repoMngr),
	)

	router := mux.NewRouter()
	router.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	loginapi.SetupHTTPHandler(loginAPI, router, tokenSvc, logger)
	signupapi.SetupHTTPHandler(signupAPI, router, tokenSvc, logger)
	deviceapi.SetupHTTPHandler(deviceAPI, router, tokenSvc, logger)

	server := http.Server{
		Addr: viper.GetString("api.http-addr"),
		Handler: handlers.CORS(
			handlers.AllowedOrigins(strings.Split(
				viper.GetString("api.allowed-origins"), ","),
			),
			handlers.AllowedHeaders([]string{
				"X-Requested-With",
				"Content-Type",
				"Authorization",
			}),
			handlers.AllowCredentials(),
			handlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS", "HEAD"}),
		)(router),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	var g run.Group
	{
		g.Add(func() error {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			return fmt.Errorf("signal received: %v", <-sig)
		}, func(err error) {
			logger.Log("msg", "program was interrupted", "err", err)
			cancel()
		})
	}
	{
		g.Add(func() error {
			logger.Log("msg", "API server is starting", "addr", server.Addr)
			return server.ListenAndServe()
		}, func(err error) {
			logger.Log("msg", "API server was interrupted", "err", err)
			logger.Log("msg", "API server shut down", "err", server.Shutdown(ctx))
		})
	}

	err = g.Run()
	logger.Log("msg", "actors stopped", "err", err)
}
