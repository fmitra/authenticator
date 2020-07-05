package token

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	redislib "github.com/go-redis/redis"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// ClientIDCookie is the cookie name used to set the token's
// ClientID value on a client.
const ClientIDCookie = "CLIENTID"

// Rediser is an interface to go-redis.
type Rediser interface {
	Get(key string) *redislib.StringCmd
	Set(key string, value interface{}, expiration time.Duration) *redislib.StatusCmd
	WithContext(ctx context.Context) *redislib.Client
	Close() error
}

// WithOTPDeliveryMethod sets a delivery method (e.g. email, phone)
// to be used as a channel for sending OTP codes related to a JWT token.
func WithOTPDeliveryMethod(method auth.DeliveryMethod) auth.TokenOption {
	return func(conf *auth.TokenConfiguration) {
		conf.DeliveryMethod = method
	}
}

// WithOTPAddress sets an address to receive a randomly generated
// OTP code. If a delivery method is configured on the token without
// a corresponding address, we will deliver the OTP code to the user's
// default sending address.
func WithOTPAddress(address string) auth.TokenOption {
	return func(conf *auth.TokenConfiguration) {
		conf.DeliveryAddress = address
	}
}

// WithRefreshableToken uses an older JWT token as a basis for creating
// a new token. ClientID hashes and the token ID will be carried over
// to the new token with an updated expiry time.
func WithRefreshableToken(token *auth.Token) auth.TokenOption {
	return func(conf *auth.TokenConfiguration) {
		conf.RefreshableToken = token
	}
}

// service is an implementation of auth.TokenService
// backed by redis.
type service struct {
	logger       log.Logger
	tokenExpiry  time.Duration
	entropy      io.Reader
	secret       []byte
	issuer       string
	db           Rediser
	otp          auth.OTPService
	cookieMaxAge int
	cookieDomain string
}

// Create creates a new, unsigned JWT token for a User
// with optional configuration settings.
func (s *service) Create(ctx context.Context, user *auth.User, state auth.TokenState, options ...auth.TokenOption) (*auth.Token, error) {
	conf := &auth.TokenConfiguration{}
	for _, opt := range options {
		opt(conf)
	}

	tokenULID, err := s.genULID(conf)
	if err != nil {
		return nil, err
	}

	clientID, clientIDHash, err := s.genClientIDAndHash(conf)
	if err != nil {
		return nil, err
	}

	code, codeHash, err := s.genOTPAndHash(conf, user)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(s.tokenExpiry).Unix()

	token := auth.Token{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Id:        tokenULID,
			Issuer:    s.issuer,
		},
		Code:         code,
		CodeHash:     codeHash,
		UserID:       user.ID,
		Email:        user.Email.String,
		Phone:        user.Phone.String,
		ClientID:     clientID,
		ClientIDHash: clientIDHash,
		State:        state,
	}

	return &token, nil
}

// Sign creates a signed JWT token string from a token struct.
func (s *service) Sign(ctx context.Context, token *auth.Token) (string, error) {
	jwtUnsigned := jwt.NewWithClaims(jwt.SigningMethodHS512, token)
	jwtSigned, err := jwtUnsigned.SignedString(s.secret)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign JWT token")
	}

	return jwtSigned, nil
}

// Validate checks that a JWT token is signed by us, unexpired, unrevoked
// and originating from a valid client. On success it will return the unpacked
// Token struct.
func (s *service) Validate(ctx context.Context, signedToken string, clientID string) (*auth.Token, error) {
	if !strings.HasPrefix(signedToken, "Bearer ") {
		return nil, auth.ErrInvalidToken("bearer token expected")
	}

	tokenParser := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method %v", token.Header["alg"])
		}

		return s.secret, nil
	}

	signedToken = strings.TrimPrefix(signedToken, "Bearer ")
	unpackedToken, err := jwt.Parse(signedToken, tokenParser)
	if err != nil {
		return nil, errors.Wrap(auth.ErrInvalidToken("token is invalid"), err.Error())
	}

	claims, ok := unpackedToken.Claims.(jwt.MapClaims)
	if !ok || !unpackedToken.Valid {
		return nil, errors.New("token claims unavailable")
	}

	var token auth.Token
	{
		b, err := json.Marshal(claims)
		if err != nil {
			return nil, errors.Wrap(err, "cannot marshal token to JSON")
		}

		err = json.Unmarshal(b, &token)
		if err != nil {
			return nil, errors.Wrap(err, "cannot unmarshall token to struct")
		}
	}

	if token.UserID == "" {
		return nil, auth.ErrInvalidToken("token is not associated with user")
	}

	if !s.isClientIDValid(clientID, token.ClientIDHash) {
		return nil, auth.ErrInvalidToken("token source is invalid")
	}

	err = s.db.WithContext(ctx).Get(token.Id).Err()
	if err == nil {
		return nil, auth.ErrInvalidToken("token is revoked")
	}

	if err == redislib.Nil {
		return &token, nil
	}

	return nil, errors.Wrap(err, "failed to check token in redis")
}

// Revoke revokes a JWT token by its ID for a specified duration.
func (s *service) Revoke(ctx context.Context, tokenID string, duration time.Duration) error {
	return s.db.WithContext(ctx).Set(tokenID, true, duration).Err()
}

// Cookie returns a secure cookie to accompany a token.
func (s *service) Cookie(ctx context.Context, token *auth.Token) *http.Cookie {
	cookie := http.Cookie{
		Name:     ClientIDCookie,
		Value:    token.ClientID,
		MaxAge:   s.cookieMaxAge,
		Domain:   s.cookieDomain,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	}

	return &cookie
}

func (s *service) isClientIDValid(clientID, clientIDHash string) bool {
	h, err := genClientIDHash(clientID)
	if err != nil {
		return false
	}

	if h != clientIDHash {
		return false
	}

	return true
}

func (s *service) genULID(conf *auth.TokenConfiguration) (string, error) {
	if conf.RefreshableToken != nil {
		return conf.RefreshableToken.StandardClaims.Id, nil
	}

	tokenULID, err := ulid.New(ulid.Now(), s.entropy)
	if err != nil {
		return "", fmt.Errorf("cannot generate unique token ID: %w", err)
	}

	return tokenULID.String(), nil
}

func (s *service) genClientIDAndHash(conf *auth.TokenConfiguration) (string, string, error) {
	if conf.RefreshableToken != nil {
		return "", conf.RefreshableToken.ClientIDHash, nil
	}

	clientID := genClientID()
	clientIDHash, err := genClientIDHash(clientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to write client ID: %w", err)
	}

	return clientID, clientIDHash, nil
}

func (s *service) genOTPAndHash(conf *auth.TokenConfiguration, user *auth.User) (string, string, error) {
	if conf.DeliveryMethod == "" {
		return "", "", nil
	}

	address := conf.DeliveryAddress
	sendToDefaultAddress := address == ""

	usePhoneNumber := conf.DeliveryMethod == auth.Phone &&
		user.IsPhoneOTPAllowed &&
		sendToDefaultAddress

	useEmailAddress := conf.DeliveryMethod == auth.Email &&
		user.IsEmailOTPAllowed &&
		sendToDefaultAddress

	if usePhoneNumber {
		address = user.Phone.String
	}

	if useEmailAddress {
		address = user.Email.String
	}

	if address == "" {
		return "", "", auth.ErrInvalidField("delivery address is not valid")
	}

	code, codeHash, err := s.otp.OTPCode(address, conf.DeliveryMethod)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate OTP code: %w", err)
	}

	return code, codeHash, nil
}

func genClientID() string {
	rand.Seed(time.Now().UnixNano())

	length := 40
	b := make([]rune, length)
	opts := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
	for i := range b {
		b[i] = opts[rand.Intn(len(opts))]
	}

	return string(b)
}

func genClientIDHash(clientID string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(clientID))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
