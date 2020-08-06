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
	"github.com/go-redis/redis/v8"

	auth "github.com/fmitra/authenticator"
)

// Webauthner is an interface to duo-labs/webauthn
type Webauthner interface {
	BeginRegistration(user webauthnLib.User, opts ...webauthnLib.RegistrationOption) (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error)
	FinishRegistration(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error)
	BeginLogin(user webauthnLib.User, opts ...webauthnLib.LoginOption) (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error)
	FinishLogin(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error)
}

// rediser is an interface to go-redis.
type rediser interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Close() error
}

// WebAuthn is a implements the WebAuthn authentication protocol.
// Under the hood it defers the actual validation to the /duo-labs/webauthn
// library and wraps the service's domain entities to provide compatibility
// with the third party library.
type WebAuthn struct {
	// maxDevices is the maximum amount of devices we allow a user
	// to register.
	maxDevices int
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
	db rediser
	// repoMngr is an instance of a RepositoryManager
	// to manage domain entitites.
	repoMngr auth.RepositoryManager
}

// BeginSignUp attempts to register a new WebAuthn capable device for a user.
func (w *WebAuthn) BeginSignUp(ctx context.Context, user *auth.User) ([]byte, error) {
	devices, err := w.repoMngr.Device().ByUserID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check devices: %w", err)
	}

	if len(devices) >= w.maxDevices {
		return nil, auth.ErrWebAuthn(fmt.Sprintf(
			"you cannot register more than %v devices", w.maxDevices,
		))
	}

	wu := User{User: user}

	credentialOptions, session, err := w.lib.BeginRegistration(&wu)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration initialization failed: %w",
			auth.ErrWebAuthn(err.Error()),
		)
	}

	return w.prepareChallenge(ctx, user, session, credentialOptions)
}

// FinishSignUp attempts to verify a registration attempt for a new WebAuthn
// capable device.
func (w *WebAuthn) FinishSignUp(ctx context.Context, user *auth.User, r *http.Request) (*auth.Device, error) {
	wu := User{User: user}

	session, err := w.retrieveSession(ctx, user)
	if err != nil {
		return nil, err
	}

	credential, err := w.lib.FinishRegistration(&wu, *session, r)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration failed: %w",
			auth.ErrWebAuthn(err.Error()),
		)
	}

	device := auth.Device{
		UserID:    user.ID,
		ClientID:  credential.ID,
		PublicKey: credential.PublicKey,
		AAGUID:    credential.Authenticator.AAGUID,
		SignCount: credential.Authenticator.SignCount,
	}

	var enableDeviceFn func(ctx context.Context, user *auth.User, device *auth.Device) error
	if user.IsDeviceAllowed {
		enableDeviceFn = w.enableAdditionalDevice
	} else {
		enableDeviceFn = w.enableNewDevice
	}

	err = enableDeviceFn(ctx, user, &device)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	return &device, nil
}

// BeginLogin attempts to authenticate a user through device ownership.
func (w *WebAuthn) BeginLogin(ctx context.Context, user *auth.User) ([]byte, error) {
	devices, err := w.repoMngr.Device().ByUserID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrWebAuthn("no devices found"))
	}

	wu := User{
		User:    user,
		Devices: devices,
	}

	assertion, session, err := w.lib.BeginLogin(&wu)
	if err != nil {
		return nil, fmt.Errorf("webauthn login request failed: %w",
			auth.ErrWebAuthn(err.Error()),
		)
	}

	return w.prepareChallenge(ctx, user, session, assertion)
}

// FinishLogin determines if a user successfully proved ownership of their device,
// thereby asserting their identity.
func (w *WebAuthn) FinishLogin(ctx context.Context, user *auth.User, r *http.Request) error {
	devices, err := w.repoMngr.Device().ByUserID(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("%v: %w", err, auth.ErrWebAuthn("no devices found"))
	}

	wu := User{
		User:    user,
		Devices: devices,
	}

	session, err := w.retrieveSession(ctx, user)
	if err != nil {
		return err
	}

	credential, err := w.lib.FinishLogin(&wu, *session, r)
	if err != nil {
		return fmt.Errorf("webauthn login failed: %w",
			auth.ErrWebAuthn(err.Error()),
		)
	}

	if credential.Authenticator.CloneWarning {
		return auth.ErrWebAuthn("device is possibly cloned")
	}

	client, err := w.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
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
		return fmt.Errorf("failed to update device sign count: %w", err)
	}

	return nil
}

func (w *WebAuthn) retrieveSession(ctx context.Context, user *auth.User) (*webauthnLib.SessionData, error) {
	sessionKey := newSessionKey(user.ID)
	b, err := w.db.Get(ctx, sessionKey).Bytes()
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrWebAuthn("webauthn session not started"))
	}

	session := webauthnLib.SessionData{}
	err = json.Unmarshal(b, &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal webauthn session: %w", err)
	}

	return &session, nil
}

func (w *WebAuthn) prepareChallenge(ctx context.Context, user *auth.User, session *webauthnLib.SessionData, credentials interface{}) ([]byte, error) {
	credentialBytes, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webauthn credentials: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webauthn session: %w", err)
	}

	sessionKey := newSessionKey(user.ID)
	expiresIn := time.Minute * 5
	err = w.db.Set(ctx, sessionKey, sessionBytes, expiresIn).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store webauthn login session: %w", err)
	}

	return credentialBytes, nil
}

func (w *WebAuthn) enableAdditionalDevice(ctx context.Context, user *auth.User, device *auth.Device) error {
	return w.repoMngr.Device().Create(ctx, device)
}

func (w *WebAuthn) enableNewDevice(ctx context.Context, user *auth.User, device *auth.Device) error {
	txClient, err := w.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return err
	}

	entity, err := txClient.WithAtomic(func() (interface{}, error) {
		user, err := txClient.User().GetForUpdate(ctx, user.ID)
		if err != nil {
			return nil, err
		}

		if err = txClient.Device().Create(ctx, device); err != nil {
			return nil, err
		}

		user.IsDeviceAllowed = true
		if err = txClient.User().Update(ctx, user); err != nil {
			return nil, err
		}

		return device, nil
	})
	if err != nil {
		return err
	}

	device = entity.(*auth.Device)
	// Propagate changes from the transaction over to the user
	// to avoid additional DB lookups
	user.IsDeviceAllowed = true

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
