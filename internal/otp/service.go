// Package otp provides 2FA codes generation.
package otp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	mathRand "math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	otpLib "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	auth "github.com/fmitra/authenticator"
)

// Secret stores a versioned secret key for cryptography functions.
type Secret struct {
	Version int
	Key     string
}

// Hash contains a hash of a OTP code and other variables
// to identify characteristics of the code.
type Hash struct {
	CodeHash       string
	Expiry         int64
	Address        string
	DeliveryMethod auth.DeliveryMethod
}

// OTP is a credential validator for User OTP codes.
type OTP struct {
	// codeLength is the length of a randomly generated code.
	codeLength int
	totpIssuer string
	secrets    []Secret
}

// OTPCode creates a random code and hash.
func (o *OTP) OTPCode(address string, method auth.DeliveryMethod) (code string, hash string, err error) {
	mathRand.Seed(time.Now().UnixNano())

	b := make([]rune, o.codeLength)
	opts := []rune("0123456789")
	for i := range b {
		b[i] = opts[mathRand.Intn(len(opts))]
	}

	c := string(b)
	h, err := toOTPHash(c, address, method)
	if err != nil {
		return "", "", err
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
		return "", errors.Wrap(err, "failed to generate secret")
	}
	encryptedKey, err := o.encrypt(key.Secret())
	if err != nil {
		return "", err
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
	if now >= otp.Expiry {
		return auth.ErrInvalidCode("code is expired")
	}

	h, err := hashString(code)
	if err != nil {
		return auth.ErrInvalidCode("code submission failed")
	}

	if h != otp.CodeHash {
		return auth.ErrInvalidCode("incorrect code provided")
	}

	return nil
}

// ValidateTOTP checks ifa User's TOTP is valid.
func (o *OTP) ValidateTOTP(user *auth.User, code string) error {
	secret, err := o.decrypt(user.TFASecret)
	if err != nil {
		return err
	}
	if totp.Validate(code, secret) {
		return nil
	}

	return auth.ErrInvalidCode("incorrect code provided")
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

func hashString(value string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(value))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func toOTPHash(code, address string, method auth.DeliveryMethod) (string, error) {
	codeHash, err := hashString(code)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash code")
	}

	expiry := time.Now().Add(time.Minute * 5).Unix()

	// format: <hash>:<expiriy>:<address>:<deliveryMethod>
	return fmt.Sprintf(
		"%s:%s:%s:%s",
		codeHash,
		strconv.FormatInt(expiry, 10),
		address,
		string(method),
	), nil
}

// FromOTPHash parses an OTP hash string to individual parts.
func FromOTPHash(otpHash string) (*Hash, error) {
	split := strings.Split(otpHash, ":")
	if len(split) != 4 {
		return nil, errors.New("incorrect hash")
	}

	expiry, err := strconv.ParseInt(split[1], 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "invalid expiry time")
	}

	o := &Hash{}
	hash := split[0]
	address := split[2]
	method := auth.DeliveryMethod(split[3])

	o.CodeHash = hash
	o.Address = address
	o.DeliveryMethod = method
	o.Expiry = expiry

	return o, nil
}
