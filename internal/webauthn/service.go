package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	webauthnProto "github.com/duo-labs/webauthn/protocol"
	webauthnLib "github.com/duo-labs/webauthn/webauthn"
	"github.com/go-redis/redis"
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

// Rediser is an interface to go-redis.
type Rediser interface {
	Get(key string) *redis.StringCmd
	Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	WithContext(ctx context.Context) *redis.Client
	Close() error
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
	// db is a redis DB to store sessions.
	db Rediser
	// repoMngr is an instance of a RepositoryManager
	// to manage domain entitites.
	repoMngr auth.RepositoryManager
}

// BeginSignUp attempts to register a new WebAuthn capable device for a user.
func (w *WebAuthn) BeginSignUp(ctx context.Context, user *auth.User) ([]byte, error) {
	wu := User{User: *user}

	credentialOptions, session, err := w.lib.BeginRegistration(&wu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize webauthn registration")
	}

	credentialBytes, err := json.Marshal(credentialOptions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn credential options")
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn registration session")
	}

	sessionKey := newSessionKey(user.ID)
	expiresIn := time.Minute * 5
	err = w.db.WithContext(ctx).Set(sessionKey, sessionBytes, expiresIn).Err()
	if err != nil {
		return nil, errors.Wrap(err, "failed to store webauthn registration session")
	}

	return credentialBytes, nil
}

// FinishSignUp attempts to verify a registration attempt for a new WebAuthn
// capable device.
func (w *WebAuthn) FinishSignUp(ctx context.Context, user *auth.User, r *http.Request) (*auth.Device, error) {
	wu := User{User: *user}
	sessionKey := newSessionKey(user.ID)
	b, err := w.db.WithContext(ctx).Get(sessionKey).Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "webauthn registration session not found")
	}

	session := webauthnLib.SessionData{}
	err = json.Unmarshal(b, &session)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal webauthn registration session")
	}

	credential, err := w.lib.FinishRegistration(&wu, session, r)
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

// BeginLogin attempts to authenticate a user through device ownership.
func (w *WebAuthn) BeginLogin(ctx context.Context, user *auth.User) ([]byte, error) {
	devices, err := w.repoMngr.Device().ByUserID(ctx, user.ID)
	if err != nil {
		return nil, errors.Wrap(err, "cannot find valid devices for user")
	}

	// TODO DRY THIS UP
	wu := User{
		User:    *user,
		Devices: devices,
	}

	assertion, session, err := w.lib.BeginLogin(&wu)
	if err != nil {
		return nil, errors.Wrap(err, "webauthn login request failed")
	}

	credentialBytes, err := json.Marshal(assertion)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn credential")
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal webauthn login session")
	}

	sessionKey := newSessionKey(user.ID)
	expiresIn := time.Minute * 5
	err = w.db.WithContext(ctx).Set(sessionKey, sessionBytes, expiresIn).Err()
	if err != nil {
		return nil, errors.Wrap(err, "failed to store webauthn login session")
	}

	return credentialBytes, nil
}

// FinishLogin determines if a user successfully proved ownership of their device,
// thereby asserting their identity.
func (w *WebAuthn) FinishLogin(ctx context.Context, user *auth.User, r *http.Request) error {
	devices, err := w.repoMngr.Device().ByUserID(ctx, user.ID)
	if err != nil {
		return errors.Wrap(err, "cannot find valid devices for user")
	}

	wu := User{
		User:    *user,
		Devices: devices,
	}

	// TODO DRY THIS UP
	sessionKey := newSessionKey(user.ID)
	b, err := w.db.WithContext(ctx).Get(sessionKey).Bytes()
	if err != nil {
		return errors.Wrap(err, "webauthn login session not found")
	}

	session := webauthnLib.SessionData{}
	err = json.Unmarshal(b, &session)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal webauthn login session")
	}

	credential, err := w.lib.FinishLogin(&wu, session, r)
	if err != nil {
		return errors.Wrap(err, "failed to authenticate user")
	}

	if credential.Authenticator.CloneWarning {
		return errors.New("webauthn device is possibly cloned")
	}

	client, err := w.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to start transaction")
	}

	deviceID := deviceID(devices, credential.ID)

	_, err = client.WithAtomic(func() (interface{}, error) {
		device, err := client.Device().GetForUpdate(ctx, deviceID)
		if err != nil {
			return nil, err
		}

		device.SignCount = credential.Authenticator.SignCount
		err = client.Device().Update(ctx, device)
		if err != nil {
			return nil, err
		}
		return device, nil
	})

	if err != nil {
		return errors.Wrap(err, "failed to update device sign count")
	}

	return nil
}

func newSessionKey(userID string) string {
	return fmt.Sprintf("%s-webauthn-session", userID)
}

func deviceID(devices []*auth.Device, credentialID []byte) string {
	var deviceID string
	{
		// TODO Update repository to support querying
		// by credential ID for updates.
		for _, device := range devices {
			if bytes.Equal(device.ClientID, credentialID) {
				deviceID = device.ID
				break
			}
		}
	}

	return deviceID
}
