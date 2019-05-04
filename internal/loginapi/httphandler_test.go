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
	"github.com/fmitra/authenticator/internal/password"
	"github.com/fmitra/authenticator/internal/test"
)

func TestLoginAPI_Login(t *testing.T) {
	validPassword := "$2a$10$zURdae3ekOWKobmadhWdROZLolGAIWrCEzjSfegV6Y/nsxJ1wqM2y"  // nolint

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
		name string
	}{
		{
			name: "Invalid token failure",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("whoops")
		})
	}
}

func TestLoginAPI_VerifyDevice(t *testing.T) {
	tt := []struct {
		name string
	}{
		{
			name: "Invalid token failure",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("whoops")
		})
	}
}

func TestLoginAPI_VerifyCode(t *testing.T) {
	tt := []struct {
		name string
	}{
		{
			name: "Invalid token failure",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("whoops")
		})
	}
}
