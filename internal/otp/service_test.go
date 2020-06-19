package otp

import (
	"database/sql"
	"testing"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
)

func TestOTPSvc_ValidateOTP(t *testing.T) {
	codeLength := 10
	svc := NewOTP(WithCodeLength(codeLength))
	code, hash, err := svc.RandomCode()
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
	svc := NewOTP(WithIssuer("authenticator.local"))
	user := &auth.User{
		IsTOTPAllowed: true,
		IsCodeAllowed: false,
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
		IsTOTPAllowed: true,
		IsCodeAllowed: false,
		TFASecret:     "VHON3V7ECQ3UNTGJ3GUGL4ATXEMD2TDK",
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
