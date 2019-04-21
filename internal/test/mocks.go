package test

import (
	"context"
	"net/http"
	"time"

	webauthnProto "github.com/duo-labs/webauthn/protocol"
	webauthnLib "github.com/duo-labs/webauthn/webauthn"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// TokenService mocks auth.TokenService interface.
type TokenService struct {
	CreateFn   func() (*auth.Token, string, error)
	SignFn     func() (string, error)
	ValidateFn func() (*auth.Token, error)
	RevokeFn   func() error
	Calls      struct {
		Create   int
		Sign     int
		Validate int
		Revoke   int
	}
}

// RepositoryManager mocks auth.RepositoryManager interface.
type RepositoryManager struct {
	NewWithTransactionFn func() (auth.RepositoryManager, error)
	WithAtomicFn         func() (interface{}, error)
	LoginHistoryFn       func() auth.LoginHistoryRepository
	DeviceFn             func() auth.DeviceRepository
	UserFn               func() auth.UserRepository
	Calls                struct {
		NewWithTransaction int
		WithAtomic         int
		LoginHistory       int
		Device             int
		User               int
	}
}

// LoginHistory mocks auth.LoginHistoryRepository.
type LoginHistoryRepository struct {
	ByUserIDFn     func() ([]*auth.LoginHistory, error)
	CreateFn       func() error
	GetForUpdateFn func() (*auth.LoginHistory, error)
	UpdateFn       func() error
	Calls          struct {
		ByUserID     int
		Create       int
		GetForUpdate int
		Update       int
	}
}

// DeviceRepository mocks auth.DeviceRepository.
type DeviceRepository struct {
	ByIDFn         func() (*auth.Device, error)
	ByClientIDFn   func() (*auth.Device, error)
	ByUserIDFn     func() ([]*auth.Device, error)
	CreateFn       func() error
	GetForUpdateFn func() (*auth.Device, error)
	UpdateFn       func() error
	Calls          struct {
		ByID         int
		ByClientID   int
		ByUserID     int
		Create       int
		GetForUpdate int
		Update       int
	}
}

// UserRepository mocks auth.UserRepository.
type UserRepository struct {
	ByIdentityFn   func() (*auth.User, error)
	GetForUpdateFn func() (*auth.User, error)
	CreateFn       func() error
	UpdateFn       func() error
	Calls          struct {
		ByIdentity   int
		GetForUpdate int
		Create       int
		Update       int
	}
}

// WebAuthnLib mocks duo-labs/webauthn third party library.
type WebAuthnLib struct {
	BeginRegistrationFn  func() (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error)
	FinishRegistrationFn func() (*webauthnLib.Credential, error)
	BeginLoginFn         func() (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error)
	FinishLoginFn        func() (*webauthnLib.Credential, error)
	Calls                struct {
		BeginRegistration  int
		FinishRegistration int
		BeginLogin         int
		FinishLogin        int
	}
}

// BeginRegistration mock.
func (m *WebAuthnLib) BeginRegistration(user webauthnLib.User, opts ...webauthnLib.RegistrationOption) (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error) {
	m.Calls.BeginRegistration++
	if m.BeginRegistrationFn != nil {
		return m.BeginRegistrationFn()
	}
	return nil, nil, errors.New("failed to begin registration")
}

// FinishRegistration mock.
func (m *WebAuthnLib) FinishRegistration(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error) {
	m.Calls.FinishRegistration++
	if m.FinishRegistrationFn != nil {
		return m.FinishRegistrationFn()
	}
	return nil, errors.New("failed to fnish registration")
}

// BeginLogin mock.
func (m *WebAuthnLib) BeginLogin(user webauthnLib.User, opts ...webauthnLib.LoginOption) (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error) {
	m.Calls.BeginLogin++
	if m.BeginLoginFn != nil {
		return m.BeginLoginFn()
	}
	return nil, nil, errors.New("failed to begin login")
}

// FinishLogin mock.
func (m *WebAuthnLib) FinishLogin(user webauthnLib.User, session webauthnLib.SessionData, r *http.Request) (*webauthnLib.Credential, error) {
	m.Calls.FinishLogin++
	if m.FinishLoginFn != nil {
		return m.FinishLoginFn()
	}

	return nil, errors.New("failed to finish login")
}

// NewWithTransaction mock.
func (m *RepositoryManager) NewWithTransaction(ctx context.Context) (auth.RepositoryManager, error) {
	m.Calls.NewWithTransaction++
	if m.NewWithTransactionFn != nil {
		return m.NewWithTransactionFn()
	}

	return m, nil
}

// WithAtomic mock.
func (m *RepositoryManager) WithAtomic(operation func() (interface{}, error)) (interface{}, error) {
	m.Calls.WithAtomic++
	if m.WithAtomicFn != nil {
		return m.WithAtomicFn()
	}
	return nil, errors.New("failed to start transaction")
}

// LoginHistory mock.
func (m *RepositoryManager) LoginHistory() auth.LoginHistoryRepository {
	m.Calls.LoginHistory++
	if m.LoginHistoryFn != nil {
		return m.LoginHistoryFn()
	}
	return &LoginHistoryRepository{}
}

// Device mock.
func (m *RepositoryManager) Device() auth.DeviceRepository {
	m.Calls.Device++
	if m.DeviceFn != nil {
		return m.DeviceFn()
	}
	return &DeviceRepository{}
}

// User mock.
func (m *RepositoryManager) User() auth.UserRepository {
	m.Calls.User++
	if m.UserFn != nil {
		return m.UserFn()
	}
	return &UserRepository{}
}

// ByIdentity mock.
func (m *UserRepository) ByIdentity(ctx context.Context, attribute, value string) (*auth.User, error) {
	m.Calls.ByIdentity++
	if m.ByIdentityFn != nil {
		return m.ByIdentityFn()
	}
	return &auth.User{}, nil
}

// GetForUpdate mock.
func (m *UserRepository) GetForUpdate(ctx context.Context, userID string) (*auth.User, error) {
	m.Calls.GetForUpdate++
	if m.GetForUpdateFn != nil {
		return m.GetForUpdateFn()
	}
	return &auth.User{}, nil
}

// Create mock.
func (m *UserRepository) Create(ctx context.Context, u *auth.User) error {
	m.Calls.Create++
	if m.CreateFn != nil {
		return m.CreateFn()
	}
	return nil
}

// Update mock.
func (m *UserRepository) Update(ctx context.Context, u *auth.User) error {
	m.Calls.Update++
	if m.UpdateFn != nil {
		return m.UpdateFn()
	}
	return nil
}

// ByID mock.
func (m *DeviceRepository) ByID(ctx context.Context, deviceID string) (*auth.Device, error) {
	m.Calls.ByID++
	if m.ByIDFn != nil {
		return m.ByIDFn()
	}
	return &auth.Device{}, nil
}

// ByClientID mock.
func (m *DeviceRepository) ByClientID(ctx context.Context, userID string, clientID []byte) (*auth.Device, error) {
	m.Calls.ByClientID++
	if m.ByClientIDFn != nil {
		return m.ByClientIDFn()
	}
	return &auth.Device{}, nil
}

// ByUserID mock.
func (m *DeviceRepository) ByUserID(ctx context.Context, userID string) ([]*auth.Device, error) {
	m.Calls.ByUserID++
	if m.ByUserIDFn != nil {
		return m.ByUserIDFn()
	}
	devices := make([]*auth.Device, 1)
	devices = append(devices, &auth.Device{})
	return devices, nil
}

// Create mock.
func (m *DeviceRepository) Create(ctx context.Context, device *auth.Device) error {
	m.Calls.Create++
	if m.CreateFn != nil {
		return m.CreateFn()
	}
	return nil
}

// GetForUpdate mock.
func (m *DeviceRepository) GetForUpdate(ctx context.Context, deviceID string) (*auth.Device, error) {
	m.Calls.GetForUpdate++
	if m.GetForUpdateFn != nil {
		return m.GetForUpdateFn()
	}
	return &auth.Device{}, nil
}

// Update mock.
func (m *DeviceRepository) Update(ctx context.Context, device *auth.Device) error {
	m.Calls.Update++
	if m.UpdateFn != nil {
		return m.UpdateFn()
	}
	return nil
}

// ByUserID mock.
func (m *LoginHistoryRepository) ByUserID(ctx context.Context, userID string, limit, offset int) ([]*auth.LoginHistory, error) {
	m.Calls.ByUserID++
	if m.ByUserIDFn != nil {
		return m.ByUserIDFn()
	}
	logins := make([]*auth.LoginHistory, 1)
	logins = append(logins, &auth.LoginHistory{})
	return logins, nil
}

// Create mock.
func (m *LoginHistoryRepository) Create(ctx context.Context, login *auth.LoginHistory) error {
	m.Calls.Create++
	if m.CreateFn != nil {
		return m.CreateFn()
	}
	return nil
}

// GetForUpdate mock.
func (m *LoginHistoryRepository) GetForUpdate(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	m.Calls.GetForUpdate++
	if m.GetForUpdateFn != nil {
		return m.GetForUpdateFn()
	}
	return &auth.LoginHistory{}, nil
}

// Update mock.
func (m *LoginHistoryRepository) Update(ctx context.Context, login *auth.LoginHistory) error {
	m.Calls.Update++
	if m.UpdateFn != nil {
		return m.UpdateFn()
	}
	return nil
}

// Create mock.
func (m *TokenService) Create(ctx context.Context, u *auth.User) (*auth.Token, string, error) {
	m.Calls.Create++
	if m.CreateFn != nil {
		return m.CreateFn()
	}
	return nil, "", errors.New("failed to create token")
}

// Sign mock.
func (m *TokenService) Sign(ctx context.Context, token *auth.Token) (string, error) {
	m.Calls.Sign++
	if m.SignFn != nil {
		return m.SignFn()
	}
	return "", errors.New("failed to sign token")
}

// Validate mock.
func (m *TokenService) Validate(ctx context.Context, signedToken string) (*auth.Token, error) {
	m.Calls.Validate++
	if m.ValidateFn != nil {
		return m.ValidateFn()
	}
	return nil, errors.New("token is not valid")
}

// Revoke mock.
func (m *TokenService) Revoke(ctx context.Context, tokenID string, duration time.Duration) error {
	m.Calls.Revoke++
	if m.RevokeFn != nil {
		return m.RevokeFn()
	}
	return errors.New("token revocation failed")
}
