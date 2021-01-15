package loginhistoryapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
	"github.com/fmitra/authenticator/internal/postgres"
	"github.com/fmitra/authenticator/internal/test"
)

func TestLoginHistoryAPI_List(t *testing.T) {
	tt := []struct {
		name            string
		statusCode      int
		errMessage      string
		user            auth.User
		path            string
		totalRecords    int
		tokenValidateFn func(userID string) func() (*auth.Token, error)
	}{
		{
			name:       "Requires authentication",
			statusCode: http.StatusUnauthorized,
			errMessage: "Bad token",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			path:         "/api/v1/login-history",
			totalRecords: 0,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return nil, auth.ErrInvalidToken("bad token")
				}
			},
		},
		{
			name:       "Returns default records",
			statusCode: http.StatusOK,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			path:         "/api/v1/login-history",
			totalRecords: 10,
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Returns offset records",
			statusCode: http.StatusOK,
			errMessage: "",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			totalRecords: 5,
			path:         "/api/v1/login-history?limit=10&offset=10",
			tokenValidateFn: func(userID string) func() (*auth.Token, error) {
				return func() (*auth.Token, error) {
					return &auth.Token{UserID: userID, State: auth.JWTAuthorized}, nil
				}
			},
		},
		{
			name:       "Fails for invalid pagination",
			statusCode: http.StatusBadRequest,
			errMessage: "Pagination param should be a number",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				IsVerified: true,
			},
			path:         "/api/v1/login-history?limit=foo&offset=bar",
			totalRecords: 0,
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

			repoMngr := postgres.TestClient(pgDB.DB)
			err = repoMngr.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			for i := 0; i < 15; i++ {
				err = repoMngr.LoginHistory().Create(ctx, &auth.LoginHistory{
					TokenID: fmt.Sprintf("%v", i),
					UserID:  tc.user.ID,
				})
				if err != nil {
					t.Fatal("failed to create login history:", err)
				}
			}

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			router := mux.NewRouter()
			tokenSvc := &test.TokenService{
				ValidateFn: tc.tokenValidateFn(tc.user.ID),
			}
			svc := NewService(
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("GET", tc.path, nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})
			rr := httptest.NewRecorder()
			test.SetAuthHeaders(req)
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error("HTTP status code does not match", cmp.Diff(rr.Code, tc.statusCode))
			}

			err = test.ValidateErrMessage(tc.errMessage, rr.Body)
			if err != nil {
				t.Error(err)
			}

			if tc.errMessage != "" {
				return
			}

			var resp listResponse
			if err = json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Error("failed to decode response:", err)
			}

			if len(resp.LoginHistory) != tc.totalRecords {
				t.Error("total records do not match", cmp.Diff(len(resp.LoginHistory), tc.totalRecords))
			}
		})
	}
}
