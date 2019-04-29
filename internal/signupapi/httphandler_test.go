package signupapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/otp"
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
		messagingCalls  int
		userGetFn       func() (*auth.User, error)
		userCreateFn    func() error
		tokenCreateFn   func() (*auth.Token, error)
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
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return nil, errors.New("database connection error")
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
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
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return &auth.User{IsVerified: true}, nil
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
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
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return errors.New("faled to create user")
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
			errMessage:  "An internal error occurred",
			loggerCount: 1,
			reqBody: []byte(`{
				"type": "email",
				"password": "swordfish",
				"identity": "jane@example.com"
			}`),
			userCreateCalls: 1,
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return nil, errors.New("failed to create token")
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
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
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
			messagingCalls:  0,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{Code: "123456"}, nil
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
			messagingCalls:  1,
			userGetFn: func() (*auth.User, error) {
				return nil, sql.ErrNoRows
			},
			userCreateFn: func() error {
				return nil
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
			messagingSvc := &test.MessagingService{}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithMessaging(messagingSvc),
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

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
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
		CreateFn: func() (*auth.Token, error) {
			return &auth.Token{Code: "123456"}, nil
		},
		SignFn: func() (string, error) {
			return "jwt-token", nil
		},
	}
	messagingSvc := &test.MessagingService{}

	svc := NewService(
		WithLogger(&test.Logger{}),
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
		WithMessaging(messagingSvc),
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

	if messagingSvc.Calls.Send != 1 {
		t.Errorf("incorrect MessagingService.Send() call count, want 1 got %v",
			messagingSvc.Calls.Send)
	}
}

func TestSignUpAPI_VerifyCode(t *testing.T) {
	codeHash := "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5" +
		"c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc51479" +
		"7ed7ddd3145464e2a0bab413"

	tt := []struct {
		name            string
		statusCode      int
		loggerCount     int
		reqBody         []byte
		userFn          func() (*auth.User, error)
		messagingCalls  int
		tokenValidateFn func() (*auth.Token, error)
		tokenCreateFn   func() (*auth.Token, error)
		tokenSignFn     func() (string, error)
	}{
		{
			name:        "User query failure",
			statusCode:  http.StatusInternalServerError,
			loggerCount: 1,
			reqBody:     []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return nil, errors.New("whoops")
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			messagingCalls: 0,
		},
		{
			name:        "Bad request failure",
			statusCode:  http.StatusBadRequest,
			loggerCount: 1,
			reqBody:     []byte(""),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			messagingCalls: 0,
		},
		{
			name:        "Code invalid failure",
			statusCode:  http.StatusBadRequest,
			loggerCount: 1,
			reqBody:     []byte(`{"code": "222444"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			messagingCalls: 0,
		},
		{
			name:        "Code validated",
			statusCode:  http.StatusOK,
			loggerCount: 0,
			reqBody:     []byte(`{"code": "123456"}`),
			userFn: func() (*auth.User, error) {
				return &auth.User{IsCodeAllowed: true}, nil
			},
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: codeHash, State: auth.JWTPreAuthorized}, nil
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{}, nil
			},
			tokenSignFn: func() (string, error) {
				return "jwt-token", nil
			},
			messagingCalls: 0,
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
				CreateFn:   tc.tokenCreateFn,
				SignFn:     tc.tokenSignFn,
			}
			otpSvc := otp.NewOTP()
			messagingSvc := &test.MessagingService{}
			svc := NewService(
				WithLogger(&test.Logger{}),
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
				WithOTP(otpSvc),
				WithMessaging(messagingSvc),
			)

			req, err := http.NewRequest(
				"POST",
				"/api/v1/signup/verify",
				bytes.NewBuffer(tc.reqBody),
			)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			req.Header.Set("AUTHORIZATION", "JWTTOKEN")
			req.AddCookie(&http.Cookie{
				Name:  "CLIENTID",
				Value: "client-id",
			})

			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Errorf("incorrect status code, want %v got %v", tc.statusCode, rr.Code)
			}

			if messagingSvc.Calls.Send != tc.messagingCalls {
				t.Errorf("incorrect MessagingService.Send() call count, want %v got %v",
					tc.messagingCalls, messagingSvc.Calls.Send)
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
