package deviceapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
		loggerCount     int
		tokenValidateFn func() (*auth.Token, error)
		userFn          func() (*auth.User, error)
		webauthnFn      func() ([]byte, error)
	}{
		{
			name:        "Authentication error with no token",
			statusCode:  http.StatusUnauthorized,
			authHeader:  false,
			errMessage:  "user is not authenticated",
			loggerCount: 1,
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
			name:        "Authentication error with bad token",
			statusCode:  http.StatusUnauthorized,
			authHeader:  true,
			errMessage:  "bad token",
			loggerCount: 1,
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
			name:        "User query error",
			statusCode:  http.StatusBadRequest,
			authHeader:  true,
			errMessage:  "no user found",
			loggerCount: 1,
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
			name:        "Non domain error",
			statusCode:  http.StatusInternalServerError,
			authHeader:  true,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
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
			name:        "Successful request",
			statusCode:  http.StatusOK,
			authHeader:  true,
			errMessage:  "",
			loggerCount: 0,
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
			logger := &test.Logger{}
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
				setAuthHeaders(req)
			}

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = validateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if logger.Calls.Log != tc.loggerCount {
				t.Errorf("incorrect calls to logger, want %v got %v",
					tc.loggerCount, logger.Calls.Log)
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
		loggerCount     int
		tokenValidateFn func() (*auth.Token, error)
		userFn          func() (*auth.User, error)
		webauthnFn      func() (*auth.Device, error)
	}{
		{
			name:        "Authentication error with no token",
			statusCode:  http.StatusUnauthorized,
			authHeader:  false,
			errMessage:  "user is not authenticated",
			loggerCount: 1,
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
			name:        "Authentication error with bad token",
			statusCode:  http.StatusUnauthorized,
			authHeader:  true,
			errMessage:  "bad token",
			loggerCount: 1,
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
			name:        "User query error",
			statusCode:  http.StatusBadRequest,
			authHeader:  true,
			errMessage:  "no user found",
			loggerCount: 1,
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
			name:        "Webauthn signup error",
			statusCode:  http.StatusInternalServerError,
			authHeader:  true,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
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
			name:        "Successful request",
			statusCode:  http.StatusCreated,
			authHeader:  true,
			errMessage:  "",
			loggerCount: 0,
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
			logger := &test.Logger{}
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
				setAuthHeaders(req)
			}

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = validateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if logger.Calls.Log != tc.loggerCount {
				t.Errorf("incorrect calls to logger, want %v got %v",
					tc.loggerCount, logger.Calls.Log)
			}
		})
	}
}

func TestDeviceAPI_Remove(t *testing.T) {
	tt := []struct {
		name        string
		statusCode  int
		authHeader  bool
		errMessage  string
		loggerCount int
		deviceFn    func() error
		reqBody     []byte
	}{
		{
			name:        "Authentication error with no token",
			statusCode:  http.StatusUnauthorized,
			authHeader:  false,
			errMessage:  "user is not authenticated",
			loggerCount: 1,
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
		{
			name:        "Invalid request format error",
			statusCode:  http.StatusBadRequest,
			authHeader:  true,
			errMessage:  "invalid JSON request",
			loggerCount: 1,
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`1`),
		},
		{
			name:        "Missing device ID error",
			statusCode:  http.StatusBadRequest,
			authHeader:  true,
			errMessage:  "missing deviceID",
			loggerCount: 1,
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"foo": "bar"}`),
		},
		{
			name:        "Device removal error",
			statusCode:  http.StatusBadRequest,
			authHeader:  true,
			errMessage:  "no device",
			loggerCount: 1,
			deviceFn: func() error {
				return auth.ErrNotFound("no device")
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
		{
			name:        "Successful request",
			statusCode:  http.StatusOK,
			authHeader:  true,
			errMessage:  "",
			loggerCount: 0,
			deviceFn: func() error {
				return nil
			},
			reqBody: []byte(`{"deviceID": "device-id"}`),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			logger := &test.Logger{}
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
				setAuthHeaders(req)
			}

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			err = validateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if logger.Calls.Log != tc.loggerCount {
				t.Errorf("incorrect calls to logger, want %v got %v",
					tc.loggerCount, logger.Calls.Log)
			}
		})
	}
}

func validateErrMessage(expectedMsg string, body *bytes.Buffer) error {
	if expectedMsg == "" {
		return nil
	}

	var errResponse map[string]map[string]string
	err := json.NewDecoder(body).Decode(&errResponse)
	if err != nil {
		return err
	}

	if errResponse["error"]["message"] != expectedMsg {
		return errors.Errorf("incorrect error resposne, want '%s' got '%s'",
			expectedMsg, errResponse["error"]["message"])
	}

	return nil
}

func setAuthHeaders(r *http.Request) {
	cookie := http.Cookie{
		Name:     "CLIENTID",
		Value:    "client-id",
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		Raw:      "client-id",
	}
	r.Header.Set("AUTHORIZATION", "JWTTOKEN")
	r.AddCookie(&cookie)
}
