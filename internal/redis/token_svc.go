package redis

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	db          Rediser
}

// Create creates a new, signed JWT token for a User.
// On success it returns a token and the unhashed ClientID.
func (s *service) Create(ctx context.Context, user *auth.User) (*auth.Token, string, error) {
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
			Issuer:    auth.Issuer,
		},
		UserID:   user.ID,
		Email:    user.Email.String,
		Phone:    user.Phone.String,
		ClientID: clientIDHash,
	}

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

// Validate checks that a JWT token is signed by us, unexpired,
// and unrevoked. On success it will return the unpacked Token struct.
func (s *service) Validate(ctx context.Context, signedToken string) (*auth.Token, error) {
	tokenParser := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}

		return s.secret, nil
	}

	unpackedToken, err := jwt.Parse(signedToken, tokenParser)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse JWT token")
	}

	claims, ok := unpackedToken.Claims.(jwt.MapClaims)
	if !ok || !unpackedToken.Valid {
		return nil, fmt.Errorf("token claims not available")
	}

	var token auth.Token
	{
		b, err := json.Marshal(claims)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal token to JSON")
		}

		err = json.Unmarshal(b, &token)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal token to auth struct")
		}
	}

	err = s.db.WithContext(ctx).Get(token.Id).Err()
	if err == nil {
		return nil, &auth.Error{Code: auth.ErrJWTRevoked}
	}

	if err == redislib.Nil {
		return &token, nil
	}

	return nil, errors.Wrap(err, "failed check token against redis")
}

// Revoke revokes a JWT token by its ID for a specified duration.
func (s *service) Revoke(ctx context.Context, tokenID string, duration time.Duration) error {
	return s.db.WithContext(ctx).Set(tokenID, true, duration).Err()
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
