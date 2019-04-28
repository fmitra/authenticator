package token

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	redislib "github.com/go-redis/redis"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

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
	logger      log.Logger
	tokenExpiry time.Duration
	entropy     io.Reader
	secret      []byte
	issuer      string
	db          Rediser
	otp         auth.OTPService
}

// Create creates a new, signed JWT token for a User.
// On success it returns a token and the unhashed ClientID.
func (s *service) Create(ctx context.Context, user *auth.User, state auth.TokenState) (*auth.Token, string, error) {
	tokenULID, err := ulid.New(ulid.Now(), s.entropy)
	if err != nil {
		return nil, "", errors.Wrap(err, "cannot generate unique token ID")
	}

	tokenID := tokenULID.String()
	clientID := genClientID()
	clientIDHash, err := genClientIDHash(clientID)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to write client ID")
	}

	expiresAt := time.Now().Add(s.tokenExpiry).Unix()
	token := auth.Token{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Id:        tokenID,
			Issuer:    s.issuer,
		},
		UserID:   user.ID,
		Email:    user.Email.String,
		Phone:    user.Phone.String,
		ClientID: clientIDHash,
		State:    state,
	}

	// OTP codes are embeded into JWT tokens in pre-authorization steps.
	// If this feature is disabled or the user is receiving an authorized token,
	// we can skip the next step and just return the token.
	if state == auth.JWTAuthorized || !user.IsCodeAllowed {
		return &token, clientID, nil
	}

	code, codeHash, err := s.otp.RandomCode()
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to generate OTP code")
	}

	token.Code = code
	token.CodeHash = codeHash

	return &token, clientID, nil
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
	tokenParser := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method %v", token.Header["alg"])
		}

		return s.secret, nil
	}

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

	if !s.isClientIDValid(clientID, token.ClientID) {
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
