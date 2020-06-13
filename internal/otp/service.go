// Package otp provides 2FA codes generation.
package otp

import (
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
	"time"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// OTP is a credential validator for User OTP codes.
type OTP struct {
	// codeLength is the length of a randomly generated code.
	codeLength int
}

// RandomCode creates a random code and hash
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

// Validate checks if a User OTP code is valid. User's may submit
// a randomly generated code sent to them through email or SMS,
// or provide a TOTP token.
func (o *OTP) Validate(user *auth.User, code string, hash string) error {
	var (
		isRandomCodeValid bool
		isTOTPValid       bool
	)

	if user.IsTOTPAllowed {
		isTOTPValid = o.isTOTPValid(code)
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

func (o *OTP) isTOTPValid(code string) bool {
	// TODO Implement this
	return false
}

func hashString(value string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(value))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
