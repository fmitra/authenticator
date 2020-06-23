package token

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
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

// Create creates a new, unsigned JWT token for a User.
// On success it returns a token and the unhashed ClientID.
func (s *service) Create(ctx context.Context, user *auth.User, state auth.TokenState) (*auth.Token, error) {
	tokenULID, err := ulid.New(ulid.Now(), s.entropy)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate unique token ID")
	}

	tokenID := tokenULID.String()
	clientID := genClientID()
	clientIDHash, err := genClientIDHash(clientID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write client ID")
	}

	expiresAt := time.Now().Add(s.tokenExpiry).Unix()
	token := auth.Token{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Id:        tokenID,
			Issuer:    s.issuer,
		},
		UserID:       user.ID,
		Email:        user.Email.String,
		Phone:        user.Phone.String,
		ClientID:     clientID,
		ClientIDHash: clientIDHash,
		State:        state,
	}

	return &token, nil
}

// CreateWithOTP creaets a new, unsigned JWT token for a User with
// an embedded OTP code to be sent to a user's address. On success it
// returns a token and the unhashed client ID.
func (s *service) CreateWithOTP(
	ctx context.Context, user *auth.User, state auth.TokenState, method auth.DeliveryMethod,
) (*auth.Token, error) {
	token, err := s.Create(ctx, user, state)
	if err != nil {
		return nil, err
	}

	if method != auth.Phone && method != auth.Email {
		return nil, auth.ErrInvalidField("invalid delivery method")
	}

	var address string
	if method == auth.Email && user.IsCodeAllowed {
		address = user.Email.String
	}

	if method == auth.Phone && user.IsCodeAllowed {
		address = user.Phone.String
	}

	if address == "" {
		return nil, auth.ErrInvalidField("delivery address is not valid")
	}

	code, codeHash, err := s.otp.OTPCode(address, method)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate OTP code")
	}

	token.Code = code
	token.CodeHash = codeHash

	return token, nil
}

// CreateWithOTP creaets a new, unsigned JWT token for a User with
// an embedded OTP code to be sent to any address. On success it
// returns a token and the unhashed client ID.
func (s *service) CreateWithOTPAndAddress(
	ctx context.Context, user *auth.User, state auth.TokenState, method auth.DeliveryMethod, addr string,
) (*auth.Token, error) {
	token, err := s.Create(ctx, user, state)
	if err != nil {
		return nil, err
	}

	if method != auth.Phone && method != auth.Email {
		return nil, auth.ErrInvalidField("invalid delivery method")
	}

	if addr == "" {
		return nil, auth.ErrInvalidField("address cannot be blank")
	}

	code, codeHash, err := s.otp.OTPCode(addr, method)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate OTP code")
	}

	token.Code = code
	token.CodeHash = codeHash

	return token, nil
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

func (s *service) Refresh(ctx context.Context, token *auth.Token, refreshKey string) (*auth.Token, error) {
	return nil, errors.New("not implemented")
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
