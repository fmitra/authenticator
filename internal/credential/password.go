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
func (p *Password) Hash(passwd auth.Credential) (auth.Credential, error) {
	// bcrypt will manage its own salt
	hash, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// TODO Should user struct define Password as a Credential?
	return auth.Credential(hash), nil
}

// Validate validates if a submitted password is valid for a
// stored password hash.
func (p *Password) Validate(ctx context.Context, user *auth.User, passwd auth.Credential) error {
	bPasswdHash := []byte(user.Password)
	bPasswd := []byte(passwd)
	return bcrypt.CompareHashAndPassword(bPasswdHash, bPasswd)
}
