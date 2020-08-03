package tokenapi

import (
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
	"github.com/fmitra/authenticator/internal/httpapi"
	"github.com/fmitra/authenticator/internal/postgres"
	"github.com/fmitra/authenticator/internal/test"
)

func TestTokenAPI_Verify(t *testing.T) {
	tt := []struct {
		name       string
		statusCode int
		tokenState auth.TokenState
	}{
		{
			name:       "Verifies authorized tokens",
			tokenState: auth.JWTAuthorized,
			statusCode: http.StatusOK,
		},
		{
			name:       "Rejects pre-authorized tokens",
			tokenState: auth.JWTPreAuthorized,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			tokenSvc := &test.TokenService{
				ValidateFn: func() (*auth.Token, error) {
					return &auth.Token{State: tc.tokenState}, nil
				},
			}
			repoMngr := &test.RepositoryManager{}
			svc := NewService(
				WithTokenService(tokenSvc),
				WithRepoManager(repoMngr),
			)

			req, err := http.NewRequest("POST", "/api/v1/token/verify", nil)
			if err != nil {
				t.Fatal("failed to create request:", err)
			}

			test.SetAuthHeaders(req)

			logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
			SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.statusCode {
				t.Error("status code does not match", cmp.Diff(rr.Code, tc.statusCode))
			}
		})
	}
}

func TestTokenAPI_Revoke(t *testing.T) {
	router := mux.NewRouter()
	tokenSvc := &test.TokenService{
		ValidateFn: func() (*auth.Token, error) {
			return &auth.Token{State: auth.JWTAuthorized}, nil
		},
		RevokeFn: func() error {
			return nil
		},
	}
	repoMngr := &test.RepositoryManager{}
	svc := NewService(
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
	)

	expectedCalls := 1
	expectedStatus := http.StatusOK

	req, err := http.NewRequest("DELETE", "/api/v1/token/mock-token-id", nil)
	if err != nil {
		t.Fatal("failed to create request:", err)
	}

	test.SetAuthHeaders(req)

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if expectedCalls != tokenSvc.Calls.Revoke {
		t.Error("TokenService.Revoke call count mismatch", cmp.Diff(
			expectedCalls, tokenSvc.Calls.Revoke,
		))
	}

	if rr.Code != expectedStatus {
		t.Error("status code does not match", cmp.Diff(rr.Code, expectedStatus))
	}
}

func TestTokenAPI_Refresh(t *testing.T) {
	router := mux.NewRouter()
	ctx := context.Background()
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	repoMngr := postgres.TestClient(pgDB.DB)
	user := &auth.User{
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		Password: "swordfish",
	}

	err = repoMngr.User().Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	tokenSvc := &test.TokenService{
		RefreshableFn: func() error {
			return nil
		},
		ValidateFn: func() (*auth.Token, error) {
			return &auth.Token{UserID: user.ID, State: auth.JWTAuthorized}, nil
		},
		CreateFn: func() (*auth.Token, error) {
			return &auth.Token{}, nil
		},
		SignFn: func() (string, error) {
			return "signed-token", nil
		},
	}
	svc := NewService(
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
	)

	req, err := http.NewRequest("POST", "/api/v1/token/refresh", nil)
	if err != nil {
		t.Fatal("failed to create request:", err)
	}

	test.SetAuthHeaders(req)

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	SetupHTTPHandler(svc, router, tokenSvc, logger, &httpapi.MockLimiterFactory{})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var (
		refreshableCallCount int = 1
		createCallCount          = 1
		signCallCount            = 1
		statusCode               = http.StatusOK
	)

	if rr.Code != statusCode {
		t.Error("status code does not match", cmp.Diff(rr.Code, statusCode))
	}

	if tokenSvc.Calls.Refreshable != refreshableCallCount {
		t.Error("TokenService.Refreshable call count does not match", cmp.Diff(
			tokenSvc.Calls.Refreshable, refreshableCallCount,
		))
	}

	if tokenSvc.Calls.Create != createCallCount {
		t.Error("TokenService.Create call count does not match", cmp.Diff(
			tokenSvc.Calls.Create, createCallCount,
		))
	}

	if tokenSvc.Calls.Sign != signCallCount {
		t.Error("TokenService.Sign call count does not match", cmp.Diff(
			tokenSvc.Calls.Sign, signCallCount,
		))
	}
}
