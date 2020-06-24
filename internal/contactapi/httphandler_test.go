package contactapi

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/test"
)

func TestContactAPI_CheckAddress(t *testing.T) {
	tt := []struct {
		user            auth.User
		reqBody         []byte
		name            string
		errMessage      string
		statusCode      int
		tokenValidateFn func(userID string) func() (*auth.Token, error)
		tokenCreateFn   func() (*auth.Token, error)
		tokenSignFn     func() (string, error)
		authHeader      bool
		messagingCalls  int
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			messagingCalls: 0,
			reqBody:        []byte(`{"address":"+15555555", "delivery_method":"phone"}`),
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			messagingCalls: 0,
			reqBody:        []byte(`{"address":"+15555555", "delivery_method":"phone"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
		},
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			messagingCalls: 0,
			reqBody:        []byte(`{"address":"+15555555", "delivery_method":"phone"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Request error with invalid address",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "address format is invalid",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			messagingCalls: 0,
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			reqBody: []byte(`{"address":"555", "delivery_method":"phone"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Successful request",
			statusCode: http.StatusAccepted,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			messagingCalls: 1,
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			reqBody: []byte(`{"address":"+6594867353", "delivery_method":"phone"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
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

			repoMngr := pg.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{}
			tokenSvc := &test.TokenService{
				ValidateFn:                tc.tokenValidateFn(tc.user.ID),
				CreateWithOTPAndAddressFn: tc.tokenCreateFn,
				SignFn:                    tc.tokenSignFn,
			}
			msgSvc := &test.MessagingService{}
			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithMessaging(msgSvc),
				WithToken(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/contact/check-address", bytes.NewBuffer(tc.reqBody))
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
				t.Error(cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			_, err = repoMngr.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Error("unable to retrieve user:", err)
			}

			if msgSvc.Calls.Send != tc.messagingCalls {
				t.Error("messaging call count mismatch", cmp.Diff(msgSvc.Calls.Send, tc.messagingCalls))
			}
		})
	}
}

func TestContactAPI_Verify(t *testing.T) {
	tt := []struct {
		user              auth.User
		reqBody           []byte
		name              string
		errMessage        string
		statusCode        int
		otpValidateFn     func(code, hash string) error
		tokenValidateFn   func(userID string) func() (*auth.Token, error)
		phone             string
		email             string
		isPhoneOTPAllowed bool
		isEmailOTPAllowed bool
		authHeader        bool
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "",
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			reqBody:           []byte(`{"code":"123"}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:address:phone",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "",
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			reqBody:           []byte(`{"code":"123"}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
		},
		{
			name:       "Add phone and enable 2FA",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "+6594867353",
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: true,
			reqBody:           []byte(`{"code":"123"}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:+6594867353:phone",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
			},
		},
		{
			name:       "Add phone and disable 2FA",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "+6594867353",
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			reqBody:           []byte(`{"code":"123", "is_disabled":true}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:+6594867353:phone",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
			},
		},
		{
			name:       "Add email and disable 2FA",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+6594867353",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "+6594867353",
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: false,
			reqBody:           []byte(`{"code":"123", "is_disabled":true}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:jane@example.com:email",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
			},
		},
		{
			name:       "Add email and enable 2FA",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+6594867353",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "jane@example.com",
			phone:             "+6594867353",
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: true,
			reqBody:           []byte(`{"code":"123"}`),
			otpValidateFn: func(code, hash string) error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:jane@example.com:email",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
			},
		},
		{
			name:       "Invalid OTP code",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "invalid code",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+6594867353",
					Valid:  true,
				},
				IsVerified: true,
			},
			email:             "",
			phone:             "+6594867353",
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: false,
			reqBody:           []byte(`{"code":"123"}`),
			otpValidateFn: func(code, hash string) error {
				return auth.ErrInvalidCode("invalid code")
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{
						UserID: userID,
						State:  auth.JWTAuthorized,
						CodeHash: fmt.Sprintf(
							"123456:%s:jane@example.com:email",
							strconv.FormatInt(time.Now().Add(time.Minute*5).Unix(), 10),
						),
					}, nil
				}
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

			repoMngr := pg.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{
				ValidateOTPFn: tc.otpValidateFn,
			}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
			}
			msgSvc := &test.MessagingService{}
			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithMessaging(msgSvc),
				WithToken(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/contact/verify", bytes.NewBuffer(tc.reqBody))
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

			if user.Phone.String != tc.phone {
				t.Error("phone mismatch", cmp.Diff(user.Phone.String, tc.phone))
			}

			if user.Email.String != tc.email {
				t.Error("email mismatch", cmp.Diff(user.Email.String, tc.email))
			}

			if user.IsPhoneOTPAllowed != tc.isPhoneOTPAllowed {
				t.Error("phone OTP mismatch", cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneOTPAllowed))
			}

			if user.IsEmailOTPAllowed != tc.isEmailOTPAllowed {
				t.Error("email OTP mismatch", cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailOTPAllowed))
			}
		})
	}
}

func TestContactAPI_Disable(t *testing.T) {
	tt := []struct {
		user              auth.User
		reqBody           []byte
		name              string
		errMessage        string
		phone             string
		email             string
		statusCode        int
		tokenValidateFn   func(userID string) func() (*auth.Token, error)
		isPhoneOTPAllowed bool
		isEmailOTPAllowed bool
		authHeader        bool
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
		},
		{
			name:       "Successful request",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+6594867353",
					Valid:  true,
				},
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: false,
			phone:             "+6594867353",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "OTP disabling failed",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "a 2FA option must be enabled to disable email OTP",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
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

			repoMngr := pg.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
			}
			msgSvc := &test.MessagingService{}
			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithMessaging(msgSvc),
				WithToken(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/contact/disable", bytes.NewBuffer(tc.reqBody))
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

			if user.Phone.String != tc.phone {
				t.Error("phone mismatch", cmp.Diff(user.Phone.String, tc.phone))
			}

			if user.Email.String != tc.email {
				t.Error("email mismatch", cmp.Diff(user.Email.String, tc.email))
			}

			if user.IsPhoneOTPAllowed != tc.isPhoneOTPAllowed {
				t.Error("phone OTP mismatch", cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneOTPAllowed))
			}

			if user.IsEmailOTPAllowed != tc.isEmailOTPAllowed {
				t.Error("email OTP mismatch", cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailOTPAllowed))
			}
		})
	}
}

func TestContactAPI_Remove(t *testing.T) {
	tt := []struct {
		user              auth.User
		reqBody           []byte
		name              string
		errMessage        string
		phone             string
		email             string
		statusCode        int
		tokenValidateFn   func(userID string) func() (*auth.Token, error)
		isPhoneOTPAllowed bool
		isEmailOTPAllowed bool
		authHeader        bool
	}{
		{
			name:       "Authentication error with no token",
			statusCode: http.StatusUnauthorized,
			authHeader: false,
			errMessage: "user is not authenticated",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Authentication error with bad token",
			statusCode: http.StatusUnauthorized,
			authHeader: true,
			errMessage: "bad token",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
		},
		{
			name:       "Successful request",
			statusCode: http.StatusOK,
			authHeader: true,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+6594867353",
					Valid:  true,
				},
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: true,
			isEmailOTPAllowed: false,
			phone:             "+6594867353",
			email:             "",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Address removal failed",
			statusCode: http.StatusBadRequest,
			authHeader: true,
			errMessage: "a 2FA option must be enabled to remove email",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			isPhoneOTPAllowed: false,
			isEmailOTPAllowed: true,
			phone:             "",
			email:             "jane@example.com",
			reqBody:           []byte(`{"delivery_method":"email"}`),
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
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

			repoMngr := pg.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{}
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
			}
			msgSvc := &test.MessagingService{}
			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithMessaging(msgSvc),
				WithToken(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/contact/remove", bytes.NewBuffer(tc.reqBody))
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

			if user.Phone.String != tc.phone {
				t.Error("phone mismatch", cmp.Diff(user.Phone.String, tc.phone))
			}

			if user.Email.String != tc.email {
				t.Error("email mismatch", cmp.Diff(user.Email.String, tc.email))
			}

			if user.IsPhoneOTPAllowed != tc.isPhoneOTPAllowed {
				t.Error("phone OTP mismatch", cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneOTPAllowed))
			}

			if user.IsEmailOTPAllowed != tc.isEmailOTPAllowed {
				t.Error("email OTP mismatch", cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailOTPAllowed))
			}
		})
	}
}

func TestContactAPI_Send(t *testing.T) {
	tt := []struct {
		user            auth.User
		reqBody         []byte
		name            string
		errMessage      string
		statusCode      int
		messagingCalls  int
		tokenCreateFn   func() (*auth.Token, error)
		tokenSignFn     func() (string, error)
		tokenValidateFn func(userID string) func() (*auth.Token, error)
		msgSendFn       func() error
	}{
		{
			name:           "Successful request",
			errMessage:     "",
			statusCode:     http.StatusAccepted,
			messagingCalls: 1,
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: false,
			},
			reqBody: []byte(`{"delivery_method":"phone"}`),
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			msgSendFn: func() error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTPreAuthorized}, nil
				}
			},
		},
		{
			name:           "OTP creation failure",
			errMessage:     "phone is not a valid delivery method",
			statusCode:     http.StatusBadRequest,
			messagingCalls: 0,
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: false,
			},
			reqBody: []byte(`{"delivery_method":"phone"}`),
			tokenCreateFn: func() (*auth.Token, error) {
				return nil, auth.ErrInvalidField("phone is not a valid delivery method")
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			msgSendFn: func() error {
				return nil
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTPreAuthorized}, nil
				}
			},
		},
		{
			name:           "Fails to deliver message",
			statusCode:     http.StatusInternalServerError,
			messagingCalls: 1,
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: false,
			},
			reqBody: []byte(`{"delivery_method":"phone"}`),
			tokenCreateFn: func() (*auth.Token, error) {
				return &auth.Token{CodeHash: "token:1:address:phone"}, nil
			},
			tokenSignFn: func() (string, error) {
				return "token", nil
			},
			msgSendFn: func() error {
				return fmt.Errorf("whoops")
			},
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTPreAuthorized}, nil
				}
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

			repoMngr := pg.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			router := mux.NewRouter()
			otpSvc := &test.OTPService{}
			tokenSvc := &test.TokenService{
				CreateWithOTPFn: tc.tokenCreateFn,
				SignFn:          tc.tokenSignFn,
				ValidateFn:      tc.tokenValidateFn(tc.user.ID),
			}
			msgSvc := test.MessagingService{
				SendFn: tc.msgSendFn,
			}
			svc := NewService(
				WithOTP(otpSvc),
				WithRepoManager(repoMngr),
				WithMessaging(&msgSvc),
				WithToken(tokenSvc),
			)

			req, err := http.NewRequest("POST", "/api/v1/contact/send", bytes.NewBuffer(tc.reqBody))
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			test.SetAuthHeaders(req)
			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error("status code mismatch", cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if msgSvc.Calls.Send != tc.messagingCalls {
				t.Error("messaging service calls mismatch",
					cmp.Diff(msgSvc.Calls.Send, tc.messagingCalls))
			}
		})
	}
}
