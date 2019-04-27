package signupapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"context"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/test"
)

func TestSignUpAPI_SignUp(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		errMessage      string
		loggerCount     int
		reqBody         []byte
		userCreateCalls int
		userGetFn       func() (*auth.User, error)
		userCreateFn    func() error
		tokenCreateFn   func() (*auth.Token, string, error)
		tokenSignFn     func() (string, error)
	}{
		{
			name:        "User query failure",
			statusCode:  http.StatusInternalServerError,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 0,
			userGetFn: func() (*auth.User, error) {
				return nil, errors.New("database connection error")
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "User already verified",
			statusCode:  http.StatusBadRequest,
			errMessage:  "cannot register user",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 0,
			userGetFn: func() (*auth.User, error) {
				return &auth.User{IsVerified: true}, nil
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "User creation failure",
			statusCode:  http.StatusInternalServerError,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 1,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return errors.New("faled to create user")
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Token creation failure",
			statusCode:  http.StatusInternalServerError,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 1,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return nil, "", errors.New("failed to create token")
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Token signing failure",
			statusCode:  http.StatusInternalServerError,
			errMessage:  "An internal error occurred",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 1,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
			},
			tokenSignFn: func() (string, error) {
				return "", errors.New("failed to sign token")
			},
		},
		{
			name:            "Bad request body",
			statusCode:      http.StatusBadRequest,
			errMessage:      "identity type must be email or phone",
			loggerCount:     1,
			reqBody:         []byte(`{}`),
			userCreateCalls: 0,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
		},
		{
			name:        "Successful request",
			statusCode:  http.StatusCreated,
			errMessage:  "",
			loggerCount: 0,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 1,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, string, error) {
				return &auth.Token{}, "client-id", nil
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
				ByIdentityFn: tc.userGetFn,
				CreateFn:     tc.userCreateFn,
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
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest(
				"POST",
				"/api/v1/signup",
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
			}

			err = validateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if logger.Calls.Log != tc.loggerCount {
				t.Errorf("incorrect calls to logger, want %v got %v",
					tc.loggerCount, logger.Calls.Log)
			}

			if repoMngr.Calls.NewWithTransaction != 0 {
				t.Errorf("incorrect RepositoryManager.NewWithTransaction() call count, want 0 got %v",
					repoMngr.Calls.NewWithTransaction)
			}

			if repoMngr.Calls.WithAtomic != 0 {
				t.Errorf("incorrect RepositoryManager.WithAtomic() call count, want 0 got %v",
					repoMngr.Calls.WithAtomic)
			}

			if userRepo.Calls.ReCreate != 0 {
				t.Errorf("incorrect UserRepository.ReCreate() call count, want 0 got %v",
					userRepo.Calls.ReCreate)
			}

			if userRepo.Calls.Create != tc.userCreateCalls {
				t.Errorf("incorrect UserRepository.Create() call count, want %v got %v",
					tc.userCreateCalls, userRepo.Calls.Create)
			}
		})
	}
}

func TestSignUpAPI_SignUpExistingUser(t *testing.T) {
	repoMngr, err := pg.NewTestClient("signupapi_signup_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pg.DropTestDB(repoMngr, "signupapi_signup_test")

	ctx := context.Background()
	user := &auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		IsVerified: false,
	}
	err = repoMngr.User().Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create uer:", err)
	}

	router := mux.NewRouter()
	logger := &test.Logger{}
	tokenSvc := &test.TokenService{
		CreateFn: func() (*auth.Token, string, error) {
			return &auth.Token{}, "client-id", nil
		},
		SignFn: func() (string, error) {
			return "jwt-token", nil
		},
	}

	svc := NewService(
		WithLogger(&test.Logger{}),
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
	)

	req, err := http.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer([]byte(`{
		"type": "email",
		"password": "swordfish",
		"identity": "jane@example.com"
	}`)))
	if err != nil {
		t.Fatal("failed to create request:", err)
	}

	SetupHTTPHandler(svc, router, tokenSvc, logger)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("incorrect status code, want %v got %v", http.StatusCreated, rr.Code)
	}

	newUser, err := repoMngr.User().ByIdentity(ctx, "Email", user.Email.String)
	if err != nil {
		t.Fatal("failed to retrieve user:", err)
	}

	if newUser.ID == user.ID {
		t.Error("user ID not reset on re-creation")
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
