package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	webauthnProto "github.com/duo-labs/webauthn/protocol"
	webauthnLib "github.com/duo-labs/webauthn/webauthn"
	redisLib "github.com/go-redis/redis"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

const (
	// OTPCodehash is a SHA512 hash of `123456`
	OTPCodeHash = "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5" +
		"c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd31" +
		"45464e2a0bab413"

	OTPCode = "123456"
)

func MockTokenHash(a, m string, t int64) string {
	addr := "jane@example.com"
	if a != "" {
		addr = a
	}

	method := "email"
	if m != "" {
		method = m
	}

	o := struct {
		CodeHash       string `json:"code_hash"`
		ExpiresAt      int64  `json:"expires_at"`
		Address        string `json:"address"`
		DeliveryMethod string `json:"delivery_method"`
	}{
		CodeHash:       OTPCodeHash,
		ExpiresAt:      t,
		Address:        addr,
		DeliveryMethod: method,
	}

	b, _ := json.Marshal(o)
	return base64.RawURLEncoding.EncodeToString(b)
}

// OTPService mocks auth.OTPService interface.
type OTPService struct {
	TOTPQRStringFn func(u *auth.User) (string, error)
	TOTPSecretFn   func(u *auth.User) (string, error)
	OTPCodeFn      func(address string, method auth.DeliveryMethod) (string, string, error)
	ValidateOTPFn  func(code, hash string) error
	ValidateTOTPFn func(u *auth.User, code string) error
	Calls          struct {
		TOTPQRString int
		TOTPSecret   int
		OTPCode      int
		ValidateOTP  int
		ValidateTOTP int
	}
}

// MessageRepository mocks auth.MessageRepository interface.
type MessageRepository struct {
	PublishFn func(ctx context.Context, msg *auth.Message) error
	RecentFn  func(ctx context.Context) (<-chan *auth.Message, <-chan error)
	Calls     struct {
		Publish int
		Recent  int
	}
}

// MessagingService mocks auth.MessagingService interface.
type MessagingService struct {
	SendFn func() error
	Calls  struct {
		Send int
	}
}

// TokenService mocks auth.TokenService interface.
type TokenService struct {
	RefreshableFn func() error
	CreateFn      func() (*auth.Token, error)
	SignFn        func() (string, error)
	ValidateFn    func() (*auth.Token, error)
	RevokeFn      func() error
	CookieFn      func() *http.Cookie
	Calls         struct {
		Refreshable int
		Create      int
		Sign        int
		Validate    int
		Revoke      int
		Cookie      int
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

// LoginHistoryRepository mocks auth.LoginHistoryRepository.
type LoginHistoryRepository struct {
	ByTokenIDFn    func() (*auth.LoginHistory, error)
	ByUserIDFn     func() ([]*auth.LoginHistory, error)
	CreateFn       func() error
	GetForUpdateFn func() (*auth.LoginHistory, error)
	UpdateFn       func() error
	Calls          struct {
		ByUserID     int
		Create       int
		GetForUpdate int
		Update       int
		ByTokenID    int
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
	RemoveFn       func() error
	Calls          struct {
		ByID         int
		ByClientID   int
		ByUserID     int
		Create       int
		GetForUpdate int
		Update       int
		Remove       int
	}
}

// UserRepository mocks auth.UserRepository.
type UserRepository struct {
	ByIdentityFn           func() (*auth.User, error)
	GetForUpdateFn         func() (*auth.User, error)
	DisableOTPFn           func() (*auth.User, error)
	RemoveDeliveryMethodFn func() (*auth.User, error)
	CreateFn               func() error
	ReCreateFn             func() error
	UpdateFn               func() error
	Calls                  struct {
		ByIdentity           int
		DisableOTP           int
		RemoveDeliveryMethod int
		GetForUpdate         int
		Create               int
		ReCreate             int
		Update               int
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

// WebAuthnService mocks auth.WebAuthnService.
type WebAuthnService struct {
	BeginSignUpFn  func() ([]byte, error)
	FinishSignUpFn func() (*auth.Device, error)
	BeginLoginFn   func() ([]byte, error)
	FinishLoginFn  func() error
	Calls          struct {
		BeginSignUp  int
		FinishSignUp int
		BeginLogin   int
		FinishLogin  int
	}
}

// Logger mocks a go-kit logger.
type Logger struct {
	LogFn func() error
	Calls struct {
		Log int
	}
}

// Rediser mocks go-redis client.
type Rediser struct {
	GetFn         func() *redisLib.StringCmd
	SetFn         func() *redisLib.StatusCmd
	WithContextFn func() *redisLib.Client
	CloseFn       func() error
	Calls         struct {
		Get         int
		Set         int
		WithContext int
		Close       int
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

// RemoveDeliveryMethod mock.
func (m *UserRepository) RemoveDeliveryMethod(ctx context.Context, userID string, method auth.DeliveryMethod) (*auth.User, error) {
	m.Calls.RemoveDeliveryMethod++
	if m.RemoveDeliveryMethodFn != nil {
		return m.RemoveDeliveryMethodFn()
	}
	return &auth.User{}, nil
}

// DisableOTP mock.
func (m *UserRepository) DisableOTP(ctx context.Context, userID string, method auth.DeliveryMethod) (*auth.User, error) {
	m.Calls.DisableOTP++
	if m.DisableOTPFn != nil {
		return m.DisableOTPFn()
	}
	return &auth.User{}, nil
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

// ReCreate mock.
func (m *UserRepository) ReCreate(ctx context.Context, u *auth.User) error {
	m.Calls.ReCreate++
	if m.ReCreateFn != nil {
		return m.ReCreateFn()
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

// Remove mock.
func (m *DeviceRepository) Remove(ct context.Context, deviceID, userID string) error {
	m.Calls.Remove++
	if m.RemoveFn != nil {
		return m.RemoveFn()
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

// ByTokenID mock.
func (m *LoginHistoryRepository) ByTokenID(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	m.Calls.ByTokenID++
	if m.ByTokenIDFn != nil {
		return m.ByTokenIDFn()
	}
	return &auth.LoginHistory{}, nil
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

// Refreshable mock.
func (m *TokenService) Refreshable(ctx context.Context, token *auth.Token, refreshToken string) error {
	m.Calls.Refreshable++
	if m.RefreshableFn != nil {
		return m.RefreshableFn()
	}
	return nil
}

// Cookie mock.
func (m *TokenService) Cookie(ctx context.Context, token *auth.Token) *http.Cookie {
	m.Calls.Cookie++
	if m.CookieFn != nil {
		return m.CookieFn()
	}
	return &http.Cookie{}
}

// Create mock.
func (m *TokenService) Create(ctx context.Context, u *auth.User, state auth.TokenState, options ...auth.TokenOption) (*auth.Token, error) {
	m.Calls.Create++
	if m.CreateFn != nil {
		return m.CreateFn()
	}
	return nil, errors.New("failed to create token")
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
func (m *TokenService) Validate(ctx context.Context, signedToken string, clientID string) (*auth.Token, error) {
	m.Calls.Validate++
	if m.ValidateFn != nil {
		return m.ValidateFn()
	}
	return nil, errors.New("token is not valid")
}

// Revoke mock.
func (m *TokenService) Revoke(ctx context.Context, tokenID string) error {
	m.Calls.Revoke++
	if m.RevokeFn != nil {
		return m.RevokeFn()
	}
	return errors.New("token revocation failed")
}

// BeginSignUp mock.
func (m *WebAuthnService) BeginSignUp(ctx context.Context, user *auth.User) ([]byte, error) {
	m.Calls.BeginSignUp++
	if m.BeginSignUpFn != nil {
		return m.BeginSignUpFn()
	}

	return nil, errors.New("failed to start signup")
}

// FinishSignUp mock.
func (m *WebAuthnService) FinishSignUp(ctx context.Context, user *auth.User, r *http.Request) (*auth.Device, error) {
	m.Calls.FinishSignUp++
	if m.FinishSignUpFn != nil {
		return m.FinishSignUpFn()
	}

	return nil, errors.New("failed to finish signup")
}

// BeginLogin mock.
func (m *WebAuthnService) BeginLogin(ctx context.Context, user *auth.User) ([]byte, error) {
	m.Calls.BeginLogin++
	if m.BeginLoginFn != nil {
		return m.BeginLoginFn()
	}

	return nil, errors.New("failed to begin login")
}

// FinishLogin mock.
func (m *WebAuthnService) FinishLogin(ctx context.Context, user *auth.User, r *http.Request) error {
	m.Calls.FinishLogin++
	if m.FinishLoginFn != nil {
		return m.FinishLoginFn()
	}

	return errors.New("failed to finsih login")
}

// Log mock.
func (m *Logger) Log(keyvals ...interface{}) error {
	m.Calls.Log++
	if m.LogFn != nil {
		return m.LogFn()
	}

	return nil
}

// Get mock.
func (m *Rediser) Get(key string) *redisLib.StringCmd {
	m.Calls.Get++
	if m.GetFn != nil {
		return m.GetFn()
	}
	return nil
}

// Set mock.
func (m *Rediser) Set(key string, v interface{}, t time.Duration) *redisLib.StatusCmd {
	m.Calls.Set++
	if m.SetFn != nil {
		return m.SetFn()
	}
	return nil
}

// WithContext mock.
func (m *Rediser) WithContext(ctxt context.Context) *redisLib.Client {
	m.Calls.WithContext++
	if m.WithContextFn != nil {
		return m.WithContextFn()
	}
	return nil
}

// Close mock.
func (m *Rediser) Close() error {
	m.Calls.Close++
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}

// Send mock.
func (m *MessagingService) Send(ctx context.Context, message, addr string, method auth.DeliveryMethod) error {
	m.Calls.Send++
	if m.SendFn != nil {
		return m.SendFn()
	}
	return nil
}

// Publish mock.
func (m *MessageRepository) Publish(ctx context.Context, msg *auth.Message) error {
	m.Calls.Publish++
	if m.PublishFn != nil {
		return m.PublishFn(ctx, msg)
	}
	return nil
}

// Recent mock.
func (m *MessageRepository) Recent(ctx context.Context) (<-chan *auth.Message, <-chan error) {
	m.Calls.Recent++
	if m.RecentFn != nil {
		return m.RecentFn(ctx)
	}

	msgc := make(chan *auth.Message)
	errc := make(chan error, 1)

	return msgc, errc
}

func (s *OTPService) TOTPQRString(u *auth.User) (string, error) {
	s.Calls.TOTPQRString++
	if s.TOTPQRStringFn != nil {
		return s.TOTPQRStringFn(u)
	}
	return "", nil
}

func (s *OTPService) TOTPSecret(u *auth.User) (string, error) {
	s.Calls.TOTPSecret++
	if s.TOTPSecretFn != nil {
		return s.TOTPSecretFn(u)
	}
	return "", nil
}

func (s *OTPService) OTPCode(address string, method auth.DeliveryMethod) (string, string, error) {
	s.Calls.OTPCode++
	if s.OTPCodeFn != nil {
		return s.OTPCodeFn(address, method)
	}
	return "", "", nil
}

func (s *OTPService) ValidateOTP(code, hash string) error {
	s.Calls.ValidateOTP++
	if s.ValidateOTPFn != nil {
		return s.ValidateOTPFn(code, hash)
	}
	return nil
}

func (s *OTPService) ValidateTOTP(u *auth.User, code string) error {
	s.Calls.ValidateTOTP++
	if s.ValidateTOTPFn != nil {
		return s.ValidateTOTPFn(u, code)
	}
	return nil
}
