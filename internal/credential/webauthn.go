package credential

import (
	"context"

	"github.com/duo-labs/webauthn/webauthn"

	auth "github.com/fmitra/authenticator"
)

// WebAuthn is a credential validator for WebAuthn authentical protocol.
// Under the hood it defers the actual validation to the /duo-labs/webauthn
// library.
type WebAuthn struct {
	// displayName is the site display name.
	displayName string
	// domain is the domain of the site.
	domain string
	// requestOrigin is the origin domain for
	// authentication requests.
	requestOrigin string
	// webauthnLib is the underlying WebAuthn library
	// used by this adapter.
	webauthnLib *webauthn.WebAuthn
}

// NewWebAuthn returns a new WebAuthn validator.
func NewWebAuthn(options ...ConfigOption) (*WebAuthn, error) {
	w := WebAuthn{}

	for _, opt := range options {
		opt(&w)
	}

	webauthnLib, err := webauthn.New(&webauthn.Config{
		RPDisplayName: w.displayName,
		RPID:          w.domain,
		RPOrigin:      w.requestOrigin,
	})
	if err != nil {
		return nil, err
	}

	w.webauthnLib = webauthnLib

	return &w, nil
}

// ConfigOption configures the validator.
type ConfigOption func(*WebAuthn)

// WithDisplayName configures the validator with a display name.
func WithDisplayName(s string) ConfigOption {
	return func(w *WebAuthn) {
		w.displayName = s
	}
}

// WithDomain configures the validator with a domain name.
func WithDomain(s string) ConfigOption {
	return func(w *WebAuthn) {
		w.domain = s
	}
}

// WithRequestOrigin configures the validator with a request origin.
func WithRequestOrigin(s string) ConfigOption {
	return func(w *WebAuthn) {
		w.requestOrigin = s
	}
}

// Validate validates if a supplied WebAuthn credential is valid
// for a user.
func (w *WebAuthn) Validate(ctx context.Context, user *auth.User, passwd auth.Credential) error {
	return nil
}

// User is a wrapper for the authenticator domain entity auth.User
// to allow compatibility with duo-lab's webauthn User interface.
type User struct {
	auth.User
	Devices []*auth.Device
}

// WebAuthnID returns the User's ID.
func (u *User) WebAuthnID() []byte {
	return []byte("")
}

// WebAuthnName returns the User's name.
func (u *User) WebAuthnName() string {
	displayName := u.Email.String
	if u.Email.String == "" {
		displayName = u.Phone.String
	}
	return displayName
}

// WebAuthnDisplayName returns the User's display name.
func (u *User) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

// WebAuthnIcon returns an Icon for the user.
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns all of the user's Devices.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	totalDevices := len(u.Devices)

	var wcs []webauthn.Credential
	{
		wcs = make([]webauthn.Credential, totalDevices)

		for idx, device := range u.Devices {
			credential := webauthn.Credential{
				ID: device.ClientID,
				PublicKey: device.PublicKey,
				Authenticator: webauthn.Authenticator{
					AAGUID: device.AAGUID,
					SignCount: device.SignCount,
				},
			}

			wcs[idx] = credential
		}
	}

	return wcs
}
