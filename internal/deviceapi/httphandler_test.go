package deviceapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestDeviceAPI_Create(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		authHeader      bool
		errMessage      string
		tokenValidateFn func() (*auth.Token, error)
		userFn          func() (*auth.User, error)
		webauthnFn      func() ([]byte, error)
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() ([]byte, error) {
				return []byte(`{"result":"challenge"}`), nil
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			tokenValidateFn: func() (*auth.Token, error) {
				return nil, auth.ErrInvalidToken("bad token")
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() ([]byte, error) {
				return []byte(`{"result":"challenge"}`), nil
			},
		},
		{
			name:       "User query error",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "no user found",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return nil, auth.ErrBadRequest("no user found")
			},
			webauthnFn: func() ([]byte, error) {
				return []byte("challenge"), nil
			},
		},
		{
			name:       "Non domain error",
			statusCode: http.StatusInternalServerError,
			authHeader: true,
			errMessage: "An internal error occurred",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return nil, errors.New("whoops")
			},
			webauthnFn: func() ([]byte, error) {
				return []byte(`{"result":"challenge"}`), nil
			},
		},
		{
			name:       "Successful request",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() ([]byte, error) {
				return []byte(`{"result":"challenge"}`), nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			webauthnSvc := &test.WebAuthnService{
				BeginSignUpFn: tc.webauthnFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return &test.UserRepository{
						ByIdentityFn: tc.userFn,
					}
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn,
			}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithWebAuthn(webauthnSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("POST", "/api/v1/device", nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDeviceAPI_Verify(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		authHeader      bool
		errMessage      string
		tokenValidateFn func() (*auth.Token, error)
		userFn          func() (*auth.User, error)
		webauthnFn      func() (*auth.Device, error)
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() (*auth.Device, error) {
				return &auth.Device{}, nil
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			tokenValidateFn: func() (*auth.Token, error) {
				return nil, auth.ErrInvalidToken("bad token")
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() (*auth.Device, error) {
				return &auth.Device{}, nil
			},
		},
		{
			name:       "User query error",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "no user found",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return nil, auth.ErrBadRequest("no user found")
			},
			webauthnFn: func() (*auth.Device, error) {
				return &auth.Device{}, nil
			},
		},
		{
			name:       "Webauthn signup error",
			statusCode: http.StatusInternalServerError,
			authHeader: true,
			errMessage: "An internal error occurred",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() (*auth.Device, error) {
				return nil, errors.New("whoops")
			},
		},
		{
			name:       "Successful request",
			statusCode: http.StatusCreated,
			authHeader: true,
			errMessage: "",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{UserID: "user-id", State: auth.JWTAuthorized}, nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			webauthnFn: func() (*auth.Device, error) {
				return &auth.Device{}, nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			webauthnSvc := &test.WebAuthnService{
				FinishSignUpFn: tc.webauthnFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return &test.UserRepository{
						ByIdentityFn: tc.userFn,
					}
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn,
			}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithWebAuthn(webauthnSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("POST", "/api/v1/device/verify", nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDeviceAPI_Remove(t *testing.T) {
	tt := []struct {
		name       string
		statusCode int
		authHeader bool
		errMessage string
		deviceFn   func() error
		reqBody    []byte
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
		{
			name:       "Invalid request format error",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "invalid JSON request",
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`1`),
		},
		{
			name:       "Missing device ID error",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "missing deviceID",
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"foo": "bar"}`),
		},
		{
			name:       "Device removal error",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "no device",
			deviceFn: func() error {
				return auth.ErrNotFound("no device")
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
		{
			name:       "Successful request",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			webauthnSvc := &test.WebAuthnService{}
			repoMngr := &test.RepositoryManager{
				DeviceFn: func() auth.DeviceRepository {
					return &test.DeviceRepository{
						RemoveFn: tc.deviceFn,
					}
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: func() (*auth.Token, error) {
					return &auth.Token{
						UserID: "user-id",
						State:  auth.JWTAuthorized,
					}, nil
				},
			}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithWebAuthn(webauthnSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("DELETE", "/api/v1/device/device-id", bytes.NewBuffer(tc.reqBody))
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
