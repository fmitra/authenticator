// Package otp provides 2FA codes generation.
package otp

import (
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
	"net/url"
	"time"

	"github.com/pkg/errors"
	otpLib "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	auth "github.com/fmitra/authenticator"
)

// OTP is a credential validator for User OTP codes.
type OTP struct {
	// codeLength is the length of a randomly generated code.
	codeLength int
	totpIssuer string
}

// RandomCode creates a random code and hash.
func (o *OTP) RandomCode() (code string, hash string, err error) {
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, o.codeLength)
	opts := []rune("0123456789")
	for i := range b {
		b[i] = opts[rand.Intn(len(opts))]
	}

	c := string(b)
	h, err := hashString(c)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to hash code")
	}

	return c, h, nil
}

// TOTPSecret assigns a TOTP secret for a user for use in code generation.
func (o *OTP) TOTPSecret(u *auth.User) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      o.totpIssuer,
		AccountName: u.DefaultName(),
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to generate secret")
	}
	return key.Secret(), nil
}

// TOTPQRString returns a string containing account details
// for TOTP code generation.
func (o *OTP) TOTPQRString(u *auth.User) string {
	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	v := url.Values{}
	v.Set("secret", u.TFASecret)
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
	return otpauth.String()
}

// Validate checks if a User OTP code is valid. User's may submit
// a randomly generated code sent to them through email or SMS,
// or provide a TOTP token.
func (o *OTP) Validate(user *auth.User, code string, hash string) error {
	var (
		isRandomCodeValid bool
		isTOTPValid       bool
	)

	if user.IsTOTPAllowed {
		isTOTPValid = o.isTOTPValid(code, user.TFASecret)
	}

	if user.IsCodeAllowed {
		isRandomCodeValid = o.isRandomCodeValid(code, hash)
	}

	if !isRandomCodeValid && !isTOTPValid {
		return auth.ErrInvalidCode("incorrect code provided")
	}

	return nil
}

func (o *OTP) isRandomCodeValid(code string, hash string) bool {
	h, err := hashString(code)
	if err != nil {
		return false
	}

	return h == hash
}

func (o *OTP) isTOTPValid(code, secret string) bool {
	return totp.Validate(code, secret)
}

func hashString(value string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(value))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
