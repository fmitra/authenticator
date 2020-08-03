package webauthn

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	webauthnProto "github.com/duo-labs/webauthn/protocol"
	webauthnLib "github.com/duo-labs/webauthn/webauthn"
	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/postgres"
	"github.com/fmitra/authenticator/internal/test"
)

func setSession(ctx context.Context, userID string, redisDB rediser) error {
	if userID == "" {
		return nil
	}

	key := newSessionKey(userID)
	b, err := json.Marshal(webauthnLib.SessionData{})
	if err != nil {
		return err
	}

	return redisDB.Set(ctx, key, b, time.Second).Err()
}

func TestWebAuthnSvc_ConfiguresService(t *testing.T) {
	_, err := NewService(
		WithDB(&test.Rediser{}),
		WithDisplayName("username"),
		WithDomain("api.authenticator.local"),
		WithRequestOrigin("app.authenticator.local"),
		WithRepoManager(&test.RepositoryManager{}),
	)
	if err != nil {
		t.Error("received error on service initialization:", err)
	}
}

func TestWebAuthnSvc_BeginSignUp(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	tt := []struct {
		name     string
		libFn    func() (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error)
		hasError bool
	}{
		{
			name: "Webauthn library failure",
			libFn: func() (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error) {
				return nil, nil, fmt.Errorf("whoops")
			},
			hasError: true,
		},
		{
			name: "Initiates signup",
			libFn: func() (*webauthnProto.CredentialCreation, *webauthnLib.SessionData, error) {
				return &webauthnProto.CredentialCreation{}, &webauthnLib.SessionData{}, nil
			},
			hasError: false,
		},
	}

	for idx, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			lib := test.WebAuthnLib{
				BeginRegistrationFn: tc.libFn,
			}
			webauthn := &WebAuthn{
				lib: &lib,
				db:  redisDB,
			}

			ctx := context.Background()
			user := &auth.User{
				ID: fmt.Sprintf("begin-signup-user-%s", strconv.Itoa(idx)),
			}
			credentials, err := webauthn.BeginSignUp(ctx, user)
			if tc.hasError && err == nil {
				t.Error("BeginSignUp should return error, not nil")
			}
			if tc.hasError && credentials != nil {
				t.Error("credentials should be nil if error occurred")
			}
			if !tc.hasError && err != nil {
				t.Error("failed to start signup:", err)
			}
			if !tc.hasError && credentials == nil {
				t.Error("failed to generated credentials")
			}
		})
	}
}

func TestWebAuthnSvc_FinishSignUpErrorHandling(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	tt := []struct {
		name   string
		libFn  func() (*webauthnLib.Credential, error)
		userID string
	}{
		{
			name: "Session retrieval failure",
			libFn: func() (*webauthnLib.Credential, error) {
				return &webauthnLib.Credential{ID: []byte("my-credential")}, nil
			},
			userID: "",
		},
		{
			name: "Webauthn library failure",
			libFn: func() (*webauthnLib.Credential, error) {
				return nil, fmt.Errorf("whoops")
			},
			userID: "finish-signup-user-webauthn-err",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			lib := test.WebAuthnLib{
				FinishRegistrationFn: tc.libFn,
			}
			webauthn := &WebAuthn{
				lib: &lib,
				db:  redisDB,
			}

			ctx := context.Background()

			err = setSession(ctx, tc.userID, redisDB)
			if err != nil {
				t.Fatal("failed to set test session:", err)
			}

			user := &auth.User{
				ID: tc.userID,
			}
			device, err := webauthn.FinishSignUp(ctx, user, nil)
			if err == nil {
				t.Error("FinishSignUp should return error, not nil")
			}
			if device != nil {
				t.Error("device should be nil if error occurred")
			}
		})
	}
}

func TestWebAuthnSvc_BeginLogin(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	tt := []struct {
		name      string
		devicesFn func() ([]*auth.Device, error)
		libFn     func() (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error)
		hasError  bool
	}{
		{
			name: "Fails with no devices",
			devicesFn: func() ([]*auth.Device, error) {
				return nil, fmt.Errorf("no devices found")
			},
			libFn: func() (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error) {
				return &webauthnProto.CredentialAssertion{}, &webauthnLib.SessionData{}, nil
			},
			hasError: true,
		},
		{
			name: "Fails on webauthn error",
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{{}}
				return devices, nil
			},
			libFn: func() (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error) {
				return nil, nil, fmt.Errorf("failed to start login")
			},
			hasError: true,
		},
		{
			name: "Returns credential bytes on success",
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{{}}
				return devices, nil
			},
			libFn: func() (*webauthnProto.CredentialAssertion, *webauthnLib.SessionData, error) {
				return &webauthnProto.CredentialAssertion{}, &webauthnLib.SessionData{}, nil
			},
			hasError: false,
		},
	}

	for idx, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			lib := test.WebAuthnLib{
				BeginLoginFn: tc.libFn,
			}
			repoMngr := &test.RepositoryManager{
				DeviceFn: func() auth.DeviceRepository {
					return &test.DeviceRepository{
						ByUserIDFn: tc.devicesFn,
					}
				},
			}
			webauthn := &WebAuthn{
				lib:      &lib,
				db:       redisDB,
				repoMngr: repoMngr,
			}
			ctx := context.Background()

			user := &auth.User{
				ID: fmt.Sprintf("begin-login-user-%s", strconv.Itoa(idx)),
			}
			b, err := webauthn.BeginLogin(ctx, user)
			if tc.hasError && err == nil {
				t.Error("BeginLogin should return error, not nil")
			}
			if tc.hasError && b != nil {
				t.Error("bytes should be nil if error occurred")
			}
			if !tc.hasError && err != nil {
				t.Error("failed to start login:", err)
			}
			if !tc.hasError && b == nil {
				t.Error("expected bytes on success, received nil")
			}
		})
	}
}

func TestWebAuthnSvc_FinishLoginErrorHandling(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	tt := []struct {
		name      string
		userID    string
		libFn     func() (*webauthnLib.Credential, error)
		devicesFn func() ([]*auth.Device, error)
		txnFn     func() (auth.RepositoryManager, error)
		commitFn  func() (interface{}, error)
	}{
		{
			name:   "Fails with no devices",
			userID: "finish-login-user-no-device",
			libFn: func() (*webauthnLib.Credential, error) {
				return &webauthnLib.Credential{}, nil
			},
			devicesFn: func() ([]*auth.Device, error) {
				return nil, fmt.Errorf("no devices found")
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return &test.RepositoryManager{}, nil
			},
			commitFn: func() (interface{}, error) {
				return nil, nil
			},
		},
		{
			name:   "Fails on missing session",
			userID: "",
			libFn: func() (*webauthnLib.Credential, error) {
				return &webauthnLib.Credential{}, nil
			},
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{{}}
				return devices, nil
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return &test.RepositoryManager{}, nil
			},
			commitFn: func() (interface{}, error) {
				return nil, nil
			},
		},
		{
			name:   "Fails on webauthn error",
			userID: "finish-login-user-webauthn",
			libFn: func() (*webauthnLib.Credential, error) {
				return nil, fmt.Errorf("failed to authenticate user")
			},
			devicesFn: func() ([]*auth.Device, error) {
				devices := make([]*auth.Device, 1)
				devices = append(devices, &auth.Device{})
				return devices, nil
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return &test.RepositoryManager{}, nil
			},
			commitFn: func() (interface{}, error) {
				return nil, nil
			},
		},
		{
			name:   "Fails on clone warning",
			userID: "finish-login-user-clone",
			libFn: func() (*webauthnLib.Credential, error) {
				credential := &webauthnLib.Credential{
					Authenticator: webauthnLib.Authenticator{
						CloneWarning: true,
					},
				}
				return credential, nil
			},
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{{}}
				return devices, nil
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return &test.RepositoryManager{}, nil
			},
			commitFn: func() (interface{}, error) {
				return nil, nil
			},
		},
		{
			name:   "Fails on transaction error",
			userID: "finish-login-user-txn",
			libFn: func() (*webauthnLib.Credential, error) {
				return &webauthnLib.Credential{}, nil
			},
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{{}}
				return devices, nil
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return nil, fmt.Errorf("failed to start new db txn")
			},
			commitFn: func() (interface{}, error) {
				return nil, nil
			},
		},
		{
			name:   "Fails on repository commit",
			userID: "finish-login-user-commit",
			libFn: func() (*webauthnLib.Credential, error) {
				credential := &webauthnLib.Credential{
					ID: []byte("my-credential"),
				}
				return credential, nil
			},
			devicesFn: func() ([]*auth.Device, error) {
				devices := []*auth.Device{
					{
						ClientID: []byte("my-credential"),
						ID:       "device-id",
					},
				}
				return devices, nil
			},
			txnFn: func() (auth.RepositoryManager, error) {
				return &test.RepositoryManager{}, nil
			},
			commitFn: func() (interface{}, error) {
				return nil, fmt.Errorf("failed to commit update")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			lib := test.WebAuthnLib{
				FinishLoginFn: tc.libFn,
			}
			repoMngr := &test.RepositoryManager{
				DeviceFn: func() auth.DeviceRepository {
					return &test.DeviceRepository{
						ByUserIDFn: tc.devicesFn,
					}
				},
				WithAtomicFn:         tc.commitFn,
				NewWithTransactionFn: tc.txnFn,
			}
			webauthn := &WebAuthn{
				lib:      &lib,
				db:       redisDB,
				repoMngr: repoMngr,
			}
			user := &auth.User{
				ID: tc.userID,
			}
			ctx := context.Background()

			err := setSession(ctx, user.ID, redisDB)
			if err != nil {
				t.Fatal("failed to set test session:", err)
			}

			err = webauthn.FinishLogin(ctx, user, nil)
			if err == nil {
				t.Error("FinishLogin should return error, not nil")
			}
		})
	}
}

func TestWebAuthnSvc_FinishSignUpSuccess(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	repoMngr := postgres.TestClient(pgDB.DB)

	ctx := context.Background()
	user := &auth.User{
		Password:        "swordfish",
		TFASecret:       "tfa_secret",
		IsDeviceAllowed: false,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = repoMngr.User().Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create uer:", err)
	}

	clientID := []byte("my-credential")
	lib := test.WebAuthnLib{
		FinishRegistrationFn: func() (*webauthnLib.Credential, error) {
			credential := &webauthnLib.Credential{
				ID: clientID,
			}
			return credential, nil
		},
	}
	webauthn := &WebAuthn{
		lib:      &lib,
		db:       redisDB,
		repoMngr: repoMngr,
	}

	err = setSession(ctx, user.ID, redisDB)
	if err != nil {
		t.Fatal("failed to set test session:", err)
	}

	device, err := webauthn.FinishSignUp(ctx, user, nil)
	if err != nil {
		t.Fatal("failed to finish signup:", err)
	}
	if device == nil {
		t.Fatal("failed to create device")
	}
	if !bytes.Equal(device.ClientID, clientID) {
		t.Errorf("client IDs do not match: want %s got %s",
			device.ClientID, clientID)
	}

	if !cmp.Equal(len(device.ID), 26) {
		t.Error("device ULID has incorrect char length", cmp.Diff(
			len(device.ID),
			26,
		))
	}

	if !user.IsDeviceAllowed {
		t.Error("user.IsDeviceAllowed should be true")
	}
}

func TestWebAuthnSvc_FinishLoginSuccess(t *testing.T) {
	redisDB, err := test.NewRedisDB()
	if err != nil {
		t.Fatal(err, "failed to create test redis database")
	}
	defer redisDB.Close()

	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	repoMngr := postgres.TestClient(pgDB.DB)

	ctx := context.Background()
	user := &auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = repoMngr.User().Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create uer:", err)
	}

	device := &auth.Device{
		UserID:    user.ID,
		ClientID:  []byte("my-credential"),
		PublicKey: []byte("public-key"),
		AAGUID:    []byte("2bc7fd09a3d64cdea6f038023d0fa49e"),
		Name:      "U2F Key",
	}
	err = repoMngr.Device().Create(ctx, device)
	if err != nil {
		t.Fatal("failed to create device:", err)
	}

	signCount := uint32(4)
	lib := test.WebAuthnLib{
		FinishLoginFn: func() (*webauthnLib.Credential, error) {
			credential := &webauthnLib.Credential{
				ID: []byte("my-credential"),
				Authenticator: webauthnLib.Authenticator{
					CloneWarning: false,
					SignCount:    signCount,
				},
			}
			return credential, nil
		},
	}

	webauthn := &WebAuthn{
		lib:      &lib,
		db:       redisDB,
		repoMngr: repoMngr,
	}

	err = setSession(ctx, user.ID, redisDB)
	if err != nil {
		t.Fatal("failed to set test session:", err)
	}

	err = webauthn.FinishLogin(ctx, user, nil)
	if err != nil {
		t.Error("failed to finish login:", err)
	}

	device, err = repoMngr.Device().ByID(ctx, device.ID)
	if err != nil {
		t.Fatal("failed to retrieve device:", err)
	}

	if device.SignCount != signCount {
		t.Errorf("device sign count does not match, want %v got %v",
			device.SignCount, signCount)
	}
}
