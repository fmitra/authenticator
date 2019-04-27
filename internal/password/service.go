package password

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	auth "github.com/fmitra/authenticator"
)

// Password is a credential validator for password authentication.
type Password struct {
	// cost is the bcrypt hash repetition. Higher cost results
	// in slower computations.
	cost int
	// minLength is the minimum length of a password.
	minLength int
	// maxLength is the maximum length of a password.
	// We enforce a maximum length to mitigate DOS attacks.
	maxLength int
}

// Hash hashes a password for storage.
func (p *Password) Hash(password string) ([]byte, error) {
	// bcrypt will manage its own salt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return []byte(""), err
	}

	return hash, nil
}

// Validate validates if a submitted password is valid for a
// stored password hash.
func (p *Password) Validate(user *auth.User, password string) error {
	bPasswdHash := []byte(user.Password)
	bPasswd := []byte(password)
	return bcrypt.CompareHashAndPassword(bPasswdHash, bPasswd)
}

// OKForUser tells us if a password meets minimum requirements to
// be set for any users.
func (p *Password) OKForUser(password string) error {
	if len(password) < p.minLength {
		return auth.ErrInvalidField(
			fmt.Sprintf("password must be at least %s characters long", strconv.Itoa(
				p.minLength,
			)),
		)
	}

	if len(password) > p.maxLength {
		return auth.ErrInvalidField(
			fmt.Sprintf("password cannot be longer than %s characters", strconv.Itoa(
				p.maxLength,
			)),
		)
	}

	return nil
}
