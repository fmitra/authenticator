package password

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	auth "github.com/fmitra/authenticator"
)

func TestPasswordSvc_ValidatePasswordRequirement(t *testing.T) {
	svc := NewPassword(
		WithCost(bcrypt.DefaultCost),
		WithMinLength(5),
		WithMaxLength(10),
	)

	tt := []struct {
		name     string
		password string
		isValid  bool
	}{
		{
			name:     "Valid password",
			password: "foobar",
			isValid:  true,
		},
		{
			name:     "Password too short",
			password: "foo",
			isValid:  false,
		},
		{
			name:     "Password too long",
			password: "thequickbrownfoxjumpedoverthelazydog",
			isValid:  false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.OKForUser(tc.password)
			if err != nil && tc.isValid {
				t.Error("expected password to be valid")
			}
		})
	}
}

func TestPasswordSvc_ValidatePassword(t *testing.T) {
	svc := NewPassword(
		WithCost(bcrypt.DefaultCost),
		WithMinLength(5),
		WithMaxLength(10),
	)

	h, err := svc.Hash("swordfish")
	if err != nil {
		t.Fatal("failed to hash password:", err)
	}

	user := &auth.User{Password: string(h)}

	err = svc.Validate(user, "swordfish-2")
	if err == nil {
		t.Error("expected password validation failure, not nil")
	}

	err = svc.Validate(user, "swordfish")
	if err != nil {
		t.Error("failed to validate password:", err)
	}
}
