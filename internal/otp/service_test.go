package otp

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
)

func TestOTPSvc_ValidateOTP(t *testing.T) {
	codeLength := 10
	svc := NewOTP(WithCodeLength(codeLength))
	code, hash, err := svc.OTPCode("jane@example.com", auth.Email)
	if err != nil {
		t.Fatal("failed to create code:", err)
	}

	if len(code) != codeLength {
		t.Errorf("incorrect code length, want %v got %v", len(code), codeLength)
	}

	err = svc.ValidateOTP(code, hash)
	if err != nil {
		t.Error("failed to validate code:", err)
	}
}

func TestOTPSvc_TOTPSecret(t *testing.T) {
	svc := NewOTP(
		WithIssuer("authenticator.local"),
		WithSecret(Secret{Version: 0, Key: "secret-key"}),
	)
	user := &auth.User{
		IsTOTPAllowed:     true,
		IsEmailOTPAllowed: false,
		Phone: sql.NullString{
			String: "+15556521234",
			Valid:  true,
		},
	}

	secret, err := svc.TOTPSecret(user)
	if err != nil {
		t.Error("expected nil error, received:", err)
	}

	if secret == "" {
		t.Error("no secret generated")
	}
}

func TestOTPSvc_TOTPQRString(t *testing.T) {
	svc := NewOTP(WithIssuer("authenticator.local"))
	user := &auth.User{
		IsTOTPAllowed:     true,
		IsEmailOTPAllowed: false,
		TFASecret:         "VHON3V7ECQ3UNTGJ3GUGL4ATXEMD2TDK",
		Phone: sql.NullString{
			String: "+15556521234",
			Valid:  true,
		},
	}
	qrString := svc.TOTPQRString(user)
	expectedString := "otpauth://totp/authenticator.local:+15556521234?algorithm=" +
		"SHA1&digits=6&issuer=authenticator.local&period=30&secret=" +
		"VHON3V7ECQ3UNTGJ3GUGL4ATXEMD2TDK"
	if !cmp.Equal(qrString, expectedString) {
		t.Error(cmp.Diff(qrString, expectedString))
	}
}

func TestOTPSvc_EncryptsWithLatestSecret(t *testing.T) {
	svc := &OTP{
		secrets: []Secret{
			{Version: 0, Key: "key-0"},
			{Version: 1, Key: "key-1"},
			{Version: 2, Key: "key-2"},
		},
	}
	secret := "some-secret-value"
	s, err := svc.encrypt(secret)
	if err != nil {
		t.Error("failed to encrypt", err)
	}
	if s == secret {
		t.Error("value not encrypted")
	}
	if !strings.HasPrefix(s, "2:") {
		t.Error("value not encrypted with latest secret")
	}

	s, err = svc.decrypt(s)
	if err != nil {
		t.Error("failed to decrypt secret", err)
	}
	if s != secret {
		t.Error("value not decrypted")
	}
}
