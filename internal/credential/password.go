package credential

import (
	"context"

	"golang.org/x/crypto/bcrypt"

	auth "github.com/fmitra/authenticator"
)

// Password is a credential validator for password authentication.
// Password validation uses bcrypt.
type Password struct {
	cost int
}

// NewPassword returns a new Password validator.
func NewPassword(cost int) *Password {
	return &Password{cost: cost}
}

// Hash hashes a password for storage.
func (p *Password) Hash(password string) ([]byte, error) {
	// bcrypt will manage its own salt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return []byte(""), err
	}

	return hash, nil
}

// Validate validates if a submitted password is valid for a
// stored password hash.
func (p *Password) Validate(ctx context.Context, user *auth.User, password string) error {
	// TODO Store user password as bytes
	bPasswdHash := []byte(user.Password)
	bPasswd := []byte(password)
	return bcrypt.CompareHashAndPassword(bPasswdHash, bPasswd)
}
