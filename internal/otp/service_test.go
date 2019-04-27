package otp

import (
	"testing"

	auth "github.com/fmitra/authenticator"
)

func TestOTPSvc_ValidateRandomCode(t *testing.T) {
	codeLength := 10
	user := &auth.User{
		IsTOTPAllowed: false,
		IsCodeAllowed: true,
	}

	svc := NewOTP(WithCodeLength(codeLength))
	code, hash, err := svc.RandomCode()
	if err != nil {
		t.Fatal("failed to create code:", err)
	}

	if len(code) != codeLength {
		t.Errorf("incorrect code length, want %v got %v", len(code), codeLength)
	}

	err = svc.Validate(user, code, hash)
	if err != nil {
		t.Error("failed to validate code:", err)
	}
}
