package credential

import (
	"encoding/json"
	"net/http"

	webauthnProto "github.com/duo-labs/webauthn/protocol"
	webauthnLib "github.com/duo-labs/webauthn/webauthn"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// Webauthner is an interface to duo-labs/webauthn
type Webauthner interface {
	BeginRegistration(user webauthnLib.User, opts ...webauthnLib.RegistrationOption) (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error)
	FinishRegistration(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error)
	BeginLogin(user webauthnLib.User, opts ...webauthnLib.LoginOption) (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error)
	FinishLogin(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error)
}

// WebAuthn is a implements the WebAuthn authentication protocol.
// Under the hood it defers the actual validation to the /duo-labs/webauthn
// library and wraps the service's domain entities to provide compatibility
// with the third party library.
type WebAuthn struct {
	// displayName is the site display name.
	displayName string
	// domain is the domain of the site.
	domain string
	// requestOrigin is the origin domain for
	// authentication requests.
	requestOrigin string
	// lib is the underlying WebAuthn library
	// used by this adapter.
	lib Webauthner
}

// NewWebAuthn returns a new WebAuthn validator.
func NewWebAuthn(options ...ConfigOption) (*WebAuthn, error) {
	w := WebAuthn{}

	for _, opt := range options {
		opt(&w)
	}

	lib, err := webauthnLib.New(&webauthnLib.Config{
		RPDisplayName: w.displayName,
		RPID:          w.domain,
		RPOrigin:      w.requestOrigin,
	})
	if err != nil {
		return nil, err
	}

	w.lib = lib

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

// Register attempts to register a new WebAuthn capable device for a user.
func (w *WebAuthn) Register(user *auth.User) ([]byte, error) {
	wu := User{User: *user}

	// TODO Handle sessionData
	credentialOptions, _, err := w.lib.BeginRegistration(&wu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize webauthn registration")
	}

	b, err := json.Marshal(credentialOptions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn credential options")
	}

	return b, nil
}

// VerifyRegistration attempts to verify a registration attempt for a new WebAuthn
// capable device.
func (w *WebAuthn) VerifyRegistration(user *auth.User, r *http.Request) (*auth.Device, error) {
	wu := User{User: *user}
	// TODO Retrieve session embedded in JWT token
	sessionData := webauthnLib.SessionData{}

	credential, err := w.lib.FinishRegistration(&wu, sessionData, r)
	if err != nil {
		return nil, errors.Wrap(err, "webauthn device registration failed")
	}

	device := auth.Device{
		UserID:    user.ID,
		ClientID:  credential.ID,
		PublicKey: credential.PublicKey,
		AAGUID:    credential.Authenticator.AAGUID,
		SignCount: credential.Authenticator.SignCount,
	}

	return &device, nil
}

// Authenticate attempts to authenticate a user through device ownership.
func (w *WebAuthn) Authenticate(user *auth.User) ([]byte, error) {
	wu := User{User: *user}

	// TODO Handle sessionData
	assertion, _, err := w.lib.BeginLogin(&wu)
	if err != nil {
		return nil, errors.Wrap(err, "webauthn login request failed")
	}

	b, err := json.Marshal(assertion)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn assertion")
	}

	return b, nil
}

// IsAuthorize determines if a user successfully proved ownership of their device,
// thereby asserting their identity.
func (w *WebAuthn) IsAuthorize(user *auth.User, r *http.Request) error {
	wu := User{User: *user}
	// TODO Retrieve session embedded in JWT token
	sessionData := webauthnLib.SessionData{}

	cred, err := w.lib.FinishLogin(&wu, sessionData, r)
	if err != nil {
		return errors.Wrap(err, "failed to authenticate user")
	}

	if cred.Authenticator.CloneWarning {
		return errors.New("webauthn device is possibly cloned")
	}

	// TODO Update sign count on the stored device
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
func (u *User) WebAuthnCredentials() []webauthnLib.Credential {
	totalDevices := len(u.Devices)

	var wcs []webauthnLib.Credential
	{
		wcs = make([]webauthnLib.Credential, totalDevices)

		for idx, device := range u.Devices {
			credential := webauthnLib.Credential{
				ID:        device.ClientID,
				PublicKey: device.PublicKey,
				Authenticator: webauthnLib.Authenticator{
					AAGUID:    device.AAGUID,
					SignCount: device.SignCount,
				},
			}

			wcs[idx] = credential
		}
	}

	return wcs
}
