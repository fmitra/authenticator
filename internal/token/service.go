package token

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	redislib "github.com/go-redis/redis"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/crypto"
)

const (
	clientIDLen     = 40
	refreshTokenLen = 40
)

const (
	// ClientIDCookie is the cookie name used to set the token's
	// ClientID value on a client.
	ClientIDCookie = "CLIENTID"
	// RefreshTokenCookie is the cookie name used to set the refresh
	// token value on a client.
	RefreshTokenCookie = "REFRESHTOKEN"
)

// RefreshToken is a token capable of refreshing an expired
// JWT token.
type RefreshToken struct {
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

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
	logger             log.Logger
	tokenExpiry        time.Duration
	refreshTokenExpiry time.Duration
	entropy            io.Reader
	secret             []byte
	issuer             string
	db                 Rediser
	repoMngr           auth.RepositoryManager
	otp                auth.OTPService
	cookieMaxAge       int
	cookieDomain       string
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

	refreshToken, refreshTokenHash, err := s.genRefreshTokenAndHash(conf)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(s.tokenExpiry).Unix()
	tfaOptions := s.genTFAOptions(user)

	token := auth.Token{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Id:        tokenULID,
			Issuer:    s.issuer,
		},
		Code:             code,
		CodeHash:         codeHash,
		RefreshToken:     refreshToken,
		RefreshTokenHash: refreshTokenHash,
		UserID:           user.ID,
		Email:            user.Email.String,
		Phone:            user.Phone.String,
		ClientID:         clientID,
		ClientIDHash:     clientIDHash,
		State:            state,
		TFAOptions:       tfaOptions,
	}

	if err = s.invalidateOldTokens(ctx, conf, &token); err != nil {
		return nil, err
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

	decoded, err := base64.RawURLEncoding.DecodeString(clientID)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode client ID")
	}

	if !isHashValid(string(decoded), token.ClientIDHash) {
		return nil, auth.ErrInvalidToken("token source is invalid")
	}

	if err := s.checkRevocation(ctx, &token); err != nil {
		return nil, err
	}

	if err := s.checkInvalidation(ctx, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

// Revoke revokes a JWT token by its ID for a specified duration.
func (s *service) Revoke(ctx context.Context, tokenID string) error {
	_, err := s.repoMngr.LoginHistory().ByTokenID(ctx, tokenID)
	if err == sql.ErrNoRows {
		return errors.Wrap(auth.ErrBadRequest("invalid tokenID"), err.Error())
	}
	if err != nil {
		return err
	}

	tx, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return fmt.Errorf("cannot start transaction: %w", err)
	}

	_, err = tx.WithAtomic(func() (interface{}, error) {
		lh, err := tx.LoginHistory().GetForUpdate(ctx, tokenID)
		if err != nil {
			return nil, err
		}

		lh.IsRevoked = true
		if err = tx.LoginHistory().Update(ctx, lh); err != nil {
			return nil, err
		}

		return lh, nil
	})
	if err != nil {
		return fmt.Errorf("failed to invalidate login history record: %w", err)
	}

	return s.db.WithContext(ctx).Set(revocationKey(tokenID), true, s.tokenExpiry).Err()
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

// Refreshable checks if a provided token can be refreshed.
func (s *service) Refreshable(ctx context.Context, token *auth.Token, refreshToken string) error {
	_, err := unpackRefreshToken(refreshToken, token.RefreshTokenHash)
	if err != nil {
		return err
	}

	lh, err := s.repoMngr.LoginHistory().ByTokenID(ctx, token.Id)
	if err != nil {
		return fmt.Errorf("failed to retrieve login history record: %w", err)
	}

	if lh.IsRevoked {
		return auth.ErrInvalidToken("token is revoked")
	}

	return nil
}

// RefreshableTill returns the last validity time of a refresh token.
func (s *service) RefreshableTill(ctx context.Context, token *auth.Token, refreshToken string) time.Time {
	r, err := unpackRefreshToken(refreshToken, token.RefreshTokenHash)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(r.ExpiresAt, 0)
}

func (s *service) genTFAOptions(user *auth.User) []auth.TFAOptions {
	options := []auth.TFAOptions{}

	if user.IsPhoneOTPAllowed {
		options = append(options, auth.OTPPhone)
	}

	if user.IsEmailOTPAllowed {
		options = append(options, auth.OTPEmail)
	}

	if user.IsTOTPAllowed {
		options = append(options, auth.TOTP)
	}

	if user.IsDeviceAllowed {
		options = append(options, auth.FIDODevice)
	}

	return options
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

	clientID, err := crypto.String(clientIDLen)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client ID: %w", err)
	}

	clientIDHash, err := crypto.Hash(clientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash client ID: %w", err)
	}

	encodedID := base64.RawURLEncoding.EncodeToString([]byte(clientID))
	return encodedID, clientIDHash, nil
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

func (s *service) genRefreshTokenAndHash(conf *auth.TokenConfiguration) (string, string, error) {
	if conf.RefreshableToken != nil {
		return "", conf.RefreshableToken.RefreshTokenHash, nil
	}

	code, err := crypto.String(refreshTokenLen)
	if err != nil {
		return "", "", err
	}

	expiresAt := time.Now().Add(s.refreshTokenExpiry).Unix()
	token := &RefreshToken{
		Code:      code,
		ExpiresAt: expiresAt,
	}

	b, err := json.Marshal(token)
	if err != nil {
		return "", "", err
	}

	h, err := crypto.Hash(string(b))
	if err != nil {
		return "", "", err
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(b)
	return encodedToken, h, nil
}

func (s *service) invalidateOldTokens(ctx context.Context, conf *auth.TokenConfiguration, token *auth.Token) error {
	proceed := conf.RefreshableToken != nil &&
		conf.DeliveryMethod != "" &&
		conf.DeliveryAddress != ""

	if !proceed {
		return nil
	}

	key := invalidationKey(token.Id)
	latestValidTimestamp := token.IssuedAt

	return s.db.WithContext(ctx).Set(key, latestValidTimestamp, s.tokenExpiry).Err()
}

func (s *service) checkRevocation(ctx context.Context, token *auth.Token) error {
	key := revocationKey(token.Id)
	err := s.db.WithContext(ctx).Get(key).Err()
	if err == nil {
		return auth.ErrInvalidToken("token is revoked")
	}
	if err == redislib.Nil {
		return nil
	}

	return fmt.Errorf("cannot lookup token revocation history: %w", err)
}

func (s *service) checkInvalidation(ctx context.Context, token *auth.Token) error {
	key := invalidationKey(token.Id)
	ts, err := s.db.WithContext(ctx).Get(key).Int64()
	if err == nil {
		if token.IssuedAt >= ts {
			return nil
		}
	}

	if err == redislib.Nil {
		return nil
	}

	return fmt.Errorf("cannot lookup token invalidation history: %w", err)
}

func invalidationKey(tokenID string) string {
	return fmt.Sprintf("%s_invalid_after", tokenID)
}

func revocationKey(tokenID string) string {
	return fmt.Sprintf("%s_is_revoked", tokenID)
}

func isHashValid(str, hash string) bool {
	h, err := crypto.Hash(str)
	if err != nil {
		return false
	}

	if h != hash {
		return false
	}

	return true
}

func unpackRefreshToken(refreshToken, refreshTokenHash string) (*RefreshToken, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("cannot decode refresh token: %w", err)
	}

	if !isHashValid(string(decoded), refreshTokenHash) {
		return nil, auth.ErrInvalidToken("refresh token is invalid")
	}

	var t RefreshToken
	err = json.Unmarshal(decoded, &t)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token format: %w", err)
	}

	now := time.Now().Unix()
	if now >= t.ExpiresAt {
		return nil, auth.ErrInvalidToken("refresh token is expired")
	}

	return &t, nil
}
