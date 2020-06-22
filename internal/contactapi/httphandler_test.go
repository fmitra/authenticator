package contactapi

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/test"
)

func TestContactAPI_CheckAddress(t *testing.T) {
	tt := []struct {
		user              auth.User
		reqBody           []byte
		name              string
		errMessage        string
		statusCode        int
		tokenValidateFn   func(userID string) func() (*auth.Token, error)
		authHeader        bool
		isPhoneOTPAllowed bool
		isEmailOTPAllowed bool
		messagingCalls    int
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
				IsVerified:        true,
				IsPhoneOTPAllowed: false,
				IsEmailOTPAllowed: true,
			},
			messagingCalls: 0,
			reqBody:        []byte(`{"address":"+15555555", "address_type":"phone"}`),
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

			user, err := repoMngr.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Error("unable to retrieve user:", err)
			}

			if user.IsPhoneOTPAllowed != tc.isPhoneOTPAllowed {
				t.Error(cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneOTPAllowed))
			}

			if user.IsEmailOTPAllowed != tc.isEmailOTPAllowed {
				t.Error(cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailOTPAllowed))
			}
			if msgSvc.Calls.Send != tc.messagingCalls {
				t.Error(cmp.Diff(msgSvc.Calls.Send, tc.messagingCalls))
			}
		})
	}
}

func TestContactAPI_Verify(t *testing.T) {
	t.Error("not implemented")
}

func TestContactAPI_Disable(t *testing.T) {
	t.Error("not implemented")
}

func TestContactAPI_Remove(t *testing.T) {
	t.Error("not implemented")
}

func TestContactAPI_Send(t *testing.T) {
	t.Error("not implemented")
}
