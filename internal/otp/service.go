// Package otp provides 2FA codes generation.
package otp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	otpLib "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/crypto"
)

// rediser is a minimal interface for go-redis
type rediser interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Close() error
}

// Secret stores a versioned secret key for cryptography functions.
type Secret struct {
	Version int
	Key     string
}

// Hash contains a hash of a OTP code and other variables
// to identify characteristics of the code.
type Hash struct {
	CodeHash       string              `json:"code_hash"`
	ExpiresAt      int64               `json:"expires_at"`
	Address        string              `json:"address"`
	DeliveryMethod auth.DeliveryMethod `json:"delivery_method"`
}

// OTP is a credential validator for User OTP codes.
type OTP struct {
	// codeLength is the length of a randomly generated code.
	codeLength int
	totpIssuer string
	secrets    []Secret
	db         rediser
}

// OTPCode creates a random code and hash.
func (o *OTP) OTPCode(address string, method auth.DeliveryMethod) (code string, hash string, err error) {
	c, err := crypto.String(o.codeLength, "0123456")
	if err != nil {
		return "", "", fmt.Errorf("cannot create random string: %w", err)
	}

	h, err := toOTPHash(c, address, method)
	if err != nil {
		return "", "", fmt.Errorf("cannot hash otp string: %w", err)
	}

	return c, h, nil
}

// TOTPSecret assigns a TOTP secret for a user for use in code generation.
// TOTP secrets are encrypted by a preconfigured secret key and decrypted
// only during validation. Encrypted keys are versioned to assist with migrations
// and backwards compatibility in the event an older secret ever needs to
// be deprecated.
func (o *OTP) TOTPSecret(u *auth.User) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      o.totpIssuer,
		AccountName: u.DefaultName(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	encryptedKey, err := o.encrypt(key.Secret())
	if err != nil {
		return "", fmt.Errorf("cannot encrypt secret: %w", err)
	}
	return encryptedKey, nil
}

// TOTPQRString returns a string containing account details
// for TOTP code generation.
func (o *OTP) TOTPQRString(u *auth.User) (string, error) {
	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	secret, err := o.decrypt(u.TFASecret)
	if err != nil {
		return "", fmt.Errorf("failed get secret for QR string: %w", err)
	}

	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", o.totpIssuer)
	v.Set("algorithm", otpLib.AlgorithmSHA1.String())
	v.Set("period", "30")
	v.Set("digits", "6")
	otpauth := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + o.totpIssuer + ":" + u.DefaultName(),
		RawQuery: v.Encode(),
	}
	return otpauth.String(), nil
}

// ValidateOTP checks if a User's OTP code is valid. User's may submit
// a randomly generated code sent to them through email or SMS.
func (o *OTP) ValidateOTP(code string, hash string) error {
	otp, err := FromOTPHash(hash)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	if now >= otp.ExpiresAt {
		return auth.ErrInvalidCode("code is expired")
	}

	h, err := crypto.Hash(code)
	if err != nil {
		return auth.ErrInvalidCode("code submission failed")
	}

	if h != otp.CodeHash {
		return auth.ErrInvalidCode("incorrect code provided")
	}

	return nil
}

// ValidateTOTP checks if a User's TOTP is valid.
// We first validate the TOTP against the user's secret key.
// If the validation passes, we then check if the code has been
// set in redis, indicating that it has been used in the past 30
// seconds. Codes that have been validated are cached to prevent
// immediate reuse.
func (o *OTP) ValidateTOTP(ctx context.Context, user *auth.User, code string) error {
	secret, err := o.decrypt(user.TFASecret)
	if err != nil {
		return fmt.Errorf("cannot decrypt secret: %w", err)
	}
	if !totp.Validate(code, secret) {
		return auth.ErrInvalidCode("incorrect code provided")
	}

	key := fmt.Sprintf("%s_%s", user.ID, code)

	err = o.db.Get(ctx, key).Err()

	// Validated code has previously been used in the past 30 seconds
	if err == nil {
		return auth.ErrInvalidCode("code is no longer valid")
	}

	// No code found in redis, indicating the code is valid. Set it to the
	// DB to prevent reuse.
	if err == redis.Nil {
		return o.db.Set(ctx, key, true, time.Second*30).Err()
	}

	return fmt.Errorf("failed to vaidated code: %w", err)
}

func (o *OTP) latestSecret() (Secret, error) {
	var secret Secret
	for _, s := range o.secrets {
		if s.Version >= secret.Version {
			secret = s
		}
	}

	if secret.Key == "" {
		return secret, fmt.Errorf("no secret key")
	}

	return secret, nil
}

func (o *OTP) secretByVersion(version int) (Secret, error) {
	var secret Secret
	for _, s := range o.secrets {
		if s.Version == version {
			secret = s
			break
		}
	}

	if secret.Key == "" {
		return secret, fmt.Errorf("no secret key found for version %v", version)
	}

	return secret, nil
}

// encrypt encrypts a string using the most recent versioned secret key
// in this service and returns the value as a base64 encoded string
// with a versioning prefix.
func (o *OTP) encrypt(s string) (string, error) {
	secret, err := o.latestSecret()
	if err != nil {
		return "", err
	}

	key := sha256.New()
	_, err = key.Write([]byte(secret.Key))
	if err != nil {
		return "", fmt.Errorf("cannot write secret: %w", err)
	}

	block, err := aes.NewCipher(key.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed create cipher block: %w", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create cipher text: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(s))
	return fmt.Sprintf("%s:%s",
		strconv.Itoa(secret.Version),
		base64.StdEncoding.EncodeToString(ciphertext),
	), nil
}

// decrypt decrypts an encrypted string using a versioned secret.
func (o *OTP) decrypt(encryptedTxt string) (string, error) {
	v := strings.Split(encryptedTxt, ":")[0]
	encryptedTxt = strings.TrimPrefix(encryptedTxt, fmt.Sprintf("%s:", v))

	version, err := strconv.Atoi(v)
	if err != nil {
		return "", fmt.Errorf("failed to determine secret version: %w", err)
	}

	secret, err := o.secretByVersion(version)
	if err != nil {
		return "", err
	}

	key := sha256.New()
	_, err = key.Write([]byte(secret.Key))
	if err != nil {
		return "", fmt.Errorf("cannot write secret: %w", err)
	}

	block, err := aes.NewCipher(key.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	if len(encryptedTxt) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	decoded, err := base64.StdEncoding.DecodeString(encryptedTxt)
	if err != nil {
		return "", fmt.Errorf("cannot decode base64 encoded secret: %w", err)
	}

	iv := decoded[:aes.BlockSize]
	decoded = decoded[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decoded, decoded)
	return string(decoded), nil
}

func toOTPHash(code, address string, method auth.DeliveryMethod) (string, error) {
	codeHash, err := crypto.Hash(code)
	if err != nil {
		return "", fmt.Errorf("failed to hash code: %w", err)
	}

	expiresAt := time.Now().Add(time.Minute * 5).Unix()

	hash := &Hash{
		CodeHash:       codeHash,
		Address:        address,
		DeliveryMethod: method,
		ExpiresAt:      expiresAt,
	}

	b, err := json.Marshal(hash)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FromOTPHash parses an OTP hash string to individual parts.
func FromOTPHash(otpHash string) (*Hash, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(otpHash)
	if err != nil {
		return nil, fmt.Errorf("cannot decode otp hash: %w", err)
	}

	var o Hash
	err = json.Unmarshal(decoded, &o)
	if err != nil {
		return nil, fmt.Errorf("invalid otp hash format: %w", err)
	}

	return &o, nil
}
