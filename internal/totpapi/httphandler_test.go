package totpapi

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
	"github.com/fmitra/authenticator/internal/postgres"
	"github.com/fmitra/authenticator/internal/test"
)

func TestTOTPAPI_Secret(t *testing.T) {
	tt := []struct {
		user            auth.User
		name            string
		errMessage      string
		tfaSecret       string
		statusCode      int
		tokenValidateFn func(userID string) func() (*auth.Token, error)
		totpSecretFn    func(u *auth.User) (string, error)
		totpQRStringFn  func(u *auth.User) string
		authHeader      bool
		isTOTPAllowed   bool
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "User is not authenticated",
			tfaSecret:  "",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
			},
			isTOTPAllowed: false,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			totpSecretFn: func(u *auth.User) (string, error) {
				return "", nil
			},
			totpQRStringFn: func(u *auth.User) string {
				return ""
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			tfaSecret:  "",
			errMessage: "Bad token",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
			},
			isTOTPAllowed: false,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
			totpSecretFn: func(u *auth.User) (string, error) {
				return "", nil
			},
			totpQRStringFn: func(u *auth.User) string {
				return ""
			},
		},
		{
			name:       "TOTP already configured",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			tfaSecret:  "",
			errMessage: "TOTP is already configured",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: true,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			totpSecretFn: func(u *auth.User) (string, error) {
				return "", nil
			},
			totpQRStringFn: func(u *auth.User) string {
				return ""
			},
		},
		{
			name:       "TOTP secret generation failure",
			statusCode: http.StatusInternalServerError,
			authHeader: true,
			errMessage: "An internal error occurred",
			tfaSecret:  "",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			totpSecretFn: func(u *auth.User) (string, error) {
				return "", fmt.Errorf("whoops")
			},
			totpQRStringFn: func(u *auth.User) string {
				return ""
			},
		},
		{
			name:       "TOTP secret success",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			tfaSecret:  "SECRET",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			totpSecretFn: func(u *auth.User) (string, error) {
				return "SECRET", nil
			},
			totpQRStringFn: func(u *auth.User) string {
				return ""
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()

			repoMngr := postgres.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{
				TOTPSecretFn: tc.totpSecretFn,
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
			}

			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("POST", "/api/v1/totp", nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error(cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			user, err := repoMngr.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Error("unable to retrieve user:", err)
			}

			if user.TFASecret != tc.tfaSecret {
				t.Error(cmp.Diff(user.TFASecret, tc.tfaSecret))
			}

			if user.IsTOTPAllowed != tc.isTOTPAllowed {
				t.Error(cmp.Diff(user.IsTOTPAllowed, tc.isTOTPAllowed))
			}
		})
	}
}

func TestTOTPAPI_Verify(t *testing.T) {
	tt := []struct {
		user            auth.User
		reqBody         []byte
		name            string
		errMessage      string
		statusCode      int
		tokenValidateFn func(userID string) func() (*auth.Token, error)
		validateTOTPFn  func(u *auth.User, code string) error
		tokenCreateFn   func() (*auth.Token, error)
		tokenSignFn     func() (string, error)
		authHeader      bool
		isTOTPAllowed   bool
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "User is not authenticated",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "Bad token",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "TOTP already configured",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "TOTP is already configured",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: true,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "TOTP configured successfully",
			statusCode: http.StatusCreated,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: true,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "Incorrect code provided",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "Incorrect code provided",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return auth.ErrInvalidCode("incorrect code provided")
			},
		},
		{
			name:       "Missing code in request",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "Code must be provided",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": ""}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "Empty body sent",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "Invalid JSON request",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       nil,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()

			repoMngr := postgres.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{
				ValidateTOTPFn: tc.validateTOTPFn,
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
				CreateFn:   tc.tokenCreateFn,
				SignFn:     tc.tokenSignFn,
			}

			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithTokenService(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/totp/configure", bytes.NewBuffer(tc.reqBody))
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error(cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			user, err := repoMngr.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Error("unable to retrieve user:", err)
			}

			if user.IsTOTPAllowed != tc.isTOTPAllowed {
				t.Error(cmp.Diff(user.IsTOTPAllowed, tc.isTOTPAllowed))
			}
		})
	}
}

func TestTOTPAPI_Remove(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		authHeader      bool
		isTOTPAllowed   bool
		user            auth.User
		errMessage      string
		reqBody         []byte
		tokenValidateFn func(userID string) func() (*auth.Token, error)
		tokenCreateFn   func() (*auth.Token, error)
		tokenSignFn     func() (string, error)
		validateTOTPFn  func(u *auth.User, code string) error
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "User is not authenticated",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: true,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "Bad token",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: true,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "TOTP not configured",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "TOTP is not enabled",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     false,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "TOTP disabled successfully",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: false,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return nil
			},
		},
		{
			name:       "Incorrect code provided",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "Incorrect code provided",
			user: auth.User{
				Password:  "swordfish",
				TFASecret: "SECRET",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified:        true,
				IsEmailOTPAllowed: true,
				IsTOTPAllowed:     true,
			},
			isTOTPAllowed: true,
			reqBody:       []byte(`{"code": "123456"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{
					CodeHash: test.MockTokenHash("", "", time.Now().Add(time.Minute*5).Unix()),
				}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			validateTOTPFn: func(u *auth.User, code string) error {
				return auth.ErrInvalidCode("incorrect code provided")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()

			repoMngr := postgres.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{
				ValidateTOTPFn: tc.validateTOTPFn,
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
				CreateFn:   tc.tokenCreateFn,
				SignFn:     tc.tokenSignFn,
			}

			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithTokenService(tokenSvc),
			)

			req, err := http.NewRequest("DELETE", "/api/v1/totp/configure", bytes.NewBuffer(tc.reqBody))
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			if tc.authHeader {
				test.SetAuthHeaders(req)
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error(cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			user, err := repoMngr.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Error("unable to retrieve user:", err)
			}

			if user.IsTOTPAllowed != tc.isTOTPAllowed {
				t.Error(cmp.Diff(user.IsTOTPAllowed, tc.isTOTPAllowed))
			}
		})
	}
}
