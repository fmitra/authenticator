// Package otp provides 2FA codes generation.
package otp

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	otpLib "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	auth "github.com/fmitra/authenticator"
)

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
}

// OTPCode creates a random code and hash.
func (o *OTP) OTPCode(address string, method auth.DeliveryMethod) (code string, hash string, err error) {
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, o.codeLength)
	opts := []rune("0123456789")
	for i := range b {
		b[i] = opts[rand.Intn(len(opts))]
	}

	c := string(b)
	h, err := toOTPHash(c, address, method)
	if err != nil {
		return "", "", err
	}

	return c, h, nil
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
	if totp.Validate(code, user.TFASecret) {
		return nil
	}

	return auth.ErrInvalidCode("incorrect code provided")
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
