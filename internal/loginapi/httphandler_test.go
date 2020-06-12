package loginapi

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/otp"
	"github.com/fmitra/authenticator/internal/password"
	"github.com/fmitra/authenticator/internal/test"
)

func TestLoginAPI_Login(t *testing.T) {
	validPassword := "$2a$10$zURdae3ekOWKobmadhWdROZLolGAIWrCEzjSfegV6Y/nsxJ1wqM2y" // nolint

	tt := []struct {
		name           string
		statusCode     int
		loggerCount    int
		reqBody        []byte
		messagingCalls int
		errMessage     string
		userFn         func() (*auth.User, error)
		tokenCreateFn  func() (*auth.Token, error)
		tokenSignFn    func() (string, error)
	}{
		{
			name:        "Non existent user failure",
			statusCode:  http.StatusBadRequest,
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 0,
			errMessage:     "invalid username or password",
			userFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Invalid password failure",
			statusCode:  http.StatusBadRequest,
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "invalid-password",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 0,
			errMessage:     "invalid username or password",
			userFn: func() (*auth.User, error) {
				return &auth.User{Password: validPassword}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "User query failure",
			statusCode:  http.StatusInternalServerError,
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 0,
			errMessage:     "An internal error occurred",
			userFn: func() (*auth.User, error) {
				return nil, errors.New("db connection failed")
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Invalid request failure",
			statusCode:  http.StatusBadRequest,
			loggerCount: 1,
			reqBody: []byte(`{
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 0,
			errMessage:     "identity type must be email or phone",
			userFn: func() (*auth.User, error) {
				return &auth.User{Password: validPassword}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Token creation failure",
			statusCode:  http.StatusInternalServerError,
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 0,
			errMessage:     "An internal error occurred",
			userFn: func() (*auth.User, error) {
				return &auth.User{Password: validPassword}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return nil, errors.New("can't create token")
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Successful request",
			statusCode:  http.StatusOK,
			loggerCount: 0,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			messagingCalls: 1,
			errMessage:     "",
			userFn: func() (*auth.User, error) {
				return &auth.User{Password: validPassword}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			logger := &test.Logger{}
			userRepo := &test.UserRepository{
				ByIdentityFn: tc.userFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return userRepo
				},
			}
			tokenSvc := &test.TokenService{
				CreateFn: tc.tokenCreateFn,
				SignFn:   tc.tokenSignFn,
			}
			messagingSvc := &test.MessagingService{}
			passwordSvc := password.NewPassword()
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithMessaging(messagingSvc),
				WithPassword(passwordSvc),
			)

			req, err := http.NewRequest(
				"POST",
				"/api/v1/login",
				bytes.NewBuffer(tc.reqBody),
			)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
				t.Error(rr.Body.String())
			}

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestLoginAPI_DeviceChallenge(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		loggerCount     int
		messagingCalls  int
		errMessage      string
		webauthnFn      func() ([]byte, error)
		userFn          func() (*auth.User, error)
		tokenValidateFn func() (*auth.Token, error)
	}{
		{
			name:           "Invalid token failure",
			statusCode:     http.StatusUnauthorized,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "token state is not supported",
			webauthnFn: func() ([]byte, error) {
				return []byte(""), nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
		},
		{
			name:           "User query failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "no user found",
			webauthnFn: func() ([]byte, error) {
				return []byte(""), nil
			},
			userFn: func() (*auth.User, error) {
				return nil, auth.ErrNotFound("no user found")
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
		},
		{
			name:           "Webauthn failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot create challenge",
			webauthnFn: func() ([]byte, error) {
				return nil, auth.ErrBadRequest("cannot create challenge")
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
		},
		{
			name:           "Successful request",
			statusCode:     http.StatusOK,
			loggerCount:    0,
			messagingCalls: 0,
			errMessage:     "",
			webauthnFn: func() ([]byte, error) {
				return []byte(""), nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			logger := &test.Logger{}
			userRepo := &test.UserRepository{
				ByIdentityFn: tc.userFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return userRepo
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn,
			}
			messagingSvc := &test.MessagingService{}
			webauthnSvc := &test.WebAuthnService{
				BeginLoginFn: tc.webauthnFn,
			}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithMessaging(messagingSvc),
				WithWebAuthn(webauthnSvc),
			)

			req, err := http.NewRequest("GET", "/api/v1/login/verify-device", nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			test.SetAuthHeaders(req)

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
				t.Error(rr.Body.String())
			}

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestLoginAPI_VerifyDevice(t *testing.T) {
	tt := []struct {
		name              string
		statusCode        int
		loggerCount       int
		messagingCalls    int
		errMessage        string
		reqBody           []byte
		webauthnFn        func() error
		userFn            func() (*auth.User, error)
		tokenCreateFn     func() (*auth.Token, error)
		tokenSignFn       func() (string, error)
		tokenValidationFn func() (*auth.Token, error)
		loginHistoryFn    func() error
	}{
		{
			name:           "Invalid token failure",
			statusCode:     http.StatusUnauthorized,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "token state is not supported",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "User query failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "user does not exist",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return nil
			},
			userFn: func() (*auth.User, error) {
				return nil, auth.ErrNotFound("user does not exist")
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Webauthn login failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "failed to login",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return auth.ErrWebAuthn("failed to login")
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Login history persisted failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot save login",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return auth.ErrBadRequest("cannot save login")
			},
		},
		{
			name:           "Token signing failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot sign token",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "", auth.ErrBadRequest("cannot sign token")
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Successful request",
			statusCode:     http.StatusOK,
			loggerCount:    0,
			messagingCalls: 0,
			errMessage:     "",
			reqBody:        []byte(""),
			webauthnFn: func() error {
				return nil
			},
			userFn: func() (*auth.User, error) {
				return &auth.User{}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			logger := &test.Logger{}
			userRepo := &test.UserRepository{
				ByIdentityFn: tc.userFn,
			}
			loginHistoryRepo := &test.LoginHistoryRepository{
				CreateFn: tc.loginHistoryFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return userRepo
				},
				LoginHistoryFn: func() auth.LoginHistoryRepository {
					return loginHistoryRepo
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidationFn,
				CreateFn:   tc.tokenCreateFn,
				SignFn:     tc.tokenSignFn,
			}
			messagingSvc := &test.MessagingService{}
			webauthnSvc := &test.WebAuthnService{
				FinishLoginFn: tc.webauthnFn,
			}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithMessaging(messagingSvc),
				WithWebAuthn(webauthnSvc),
			)

			req, err := http.NewRequest(
				"POST",
				"/api/v1/login/verify-device",
				bytes.NewBuffer(tc.reqBody),
			)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			test.SetAuthHeaders(req)

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
				t.Error(rr.Body.String())
			}

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestLoginAPI_VerifyCode(t *testing.T) {
	codeHash := "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5" +
		"c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc51479" +
		"7ed7ddd3145464e2a0bab413"

	tt := []struct {
		name              string
		statusCode        int
		loggerCount       int
		messagingCalls    int
		reqBody           []byte
		errMessage        string
		userFn            func() (*auth.User, error)
		tokenCreateFn     func() (*auth.Token, error)
		tokenSignFn       func() (string, error)
		tokenValidationFn func() (*auth.Token, error)
		loginHistoryFn    func() error
	}{
		{
			name:           "Invalid token failure",
			statusCode:     http.StatusUnauthorized,
			loggerCount:    1,
			messagingCalls: 0,
			reqBody:        []byte(`{"code": "123456"}`),
			errMessage:     "token state is not supported",
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "User query failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "user does not exist",
			reqBody:        []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return nil, auth.ErrNotFound("user does not exist")
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Invalid OTP code failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "incorrect code provided",
			reqBody:        []byte(`{"code": "222222"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Token creation failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot create token",
			reqBody:        []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return nil, auth.ErrBadRequest("cannot create token")
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Persist login history failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot save history",
			reqBody:        []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return auth.ErrBadRequest("cannot save history")
			},
		},
		{
			name:           "Token signing failure",
			statusCode:     http.StatusBadRequest,
			loggerCount:    1,
			messagingCalls: 0,
			errMessage:     "cannot sign token",
			reqBody:        []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "", auth.ErrBadRequest("cannot sign token")
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
		{
			name:           "Successful request",
			statusCode:     http.StatusOK,
			loggerCount:    0,
			messagingCalls: 0,
			errMessage:     "",
			reqBody:        []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			tokenValidationFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			loginHistoryFn: func() error {
				return nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			logger := &test.Logger{}
			userRepo := &test.UserRepository{
				ByIdentityFn: tc.userFn,
			}
			loginHistoryRepo := &test.LoginHistoryRepository{
				CreateFn: tc.loginHistoryFn,
			}
			repoMngr := &test.RepositoryManager{
				UserFn: func() auth.UserRepository {
					return userRepo
				},
				LoginHistoryFn: func() auth.LoginHistoryRepository {
					return loginHistoryRepo
				},
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidationFn,
				CreateFn:   tc.tokenCreateFn,
				SignFn:     tc.tokenSignFn,
			}
			messagingSvc := &test.MessagingService{}
			otpSvc := otp.NewOTP()
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithMessaging(messagingSvc),
				WithOTP(otpSvc),
			)

			req, err := http.NewRequest(
				"POST",
				"/api/v1/login/verify-code",
				bytes.NewBuffer(tc.reqBody),
			)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			test.SetAuthHeaders(req)

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
				t.Error(rr.Body.String())
			}

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
