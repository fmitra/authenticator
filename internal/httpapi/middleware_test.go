package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestHTTPAPI_RefreshTokenMiddleware(t *testing.T) {
	refreshTokenMock := "2e147090cd3d455da10896213649e49d" // #nosec
	responseMock := []byte(`{"foo":"bar"}`)
	handler := func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		refreshToken := GetRefreshToken(r)
		if refreshToken != refreshTokenMock {
			t.Error("refresh token does not match", cmp.Diff(refreshToken, refreshTokenMock))
		}

		return responseMock, nil
	}
	tokenSvc := test.TokenService{
		ValidateFn: func() (*auth.Token, error) {
			return &auth.Token{State: auth.JWTAuthorized}, nil
		},
	}

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		t.Fatal("failed to create mock request:", err)
	}

	r.Header.Set("AUTHORIZATION", "JWTTOKEN")

	var cookie http.Cookie
	{
		cookie = http.Cookie{
			Name:     "CLIENTID",
			Value:    "client-id",
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			Raw:      "client-id",
		}
		r.AddCookie(&cookie)
	}
	{
		cookie = http.Cookie{
			Name:     "REFRESHTOKEN",
			Value:    refreshTokenMock,
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			Raw:      refreshTokenMock,
		}
		r.AddCookie(&cookie)
	}

	var h JSONAPIHandler
	h = AuthMiddleware(handler, &tokenSvc, auth.JWTAuthorized)
	h = RefreshTokenMiddleware(h)

	v, err := h(w, r)
	if err != nil {
		t.Error("expected nil error:", err)
	}

	b, ok := v.([]byte)
	if !ok {
		t.Error("unexpected response type")
	}

	if !cmp.Equal(b, responseMock) {
		t.Error("response does not match", cmp.Diff(b, responseMock))
	}
}

func TestHTTPAPI_AuthMiddleware(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		return []byte(`{"foo":"bar"}`), nil
	}

	tt := []struct {
		name            string
		tokenValidateFn func() (*auth.Token, error)
		hasTokenHeader  bool
		hasCookieHeader bool
		errMessage      string
		tokenState      auth.TokenState
	}{
		{
			name:            "Not authenticated failure",
			hasTokenHeader:  false,
			hasCookieHeader: true,
			tokenState:      auth.JWTAuthorized,
			errMessage:      "user is not authenticated",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
		},
		{
			name:            "Invalid token source failure",
			hasTokenHeader:  true,
			hasCookieHeader: false,
			tokenState:      auth.JWTAuthorized,
			errMessage:      "token source is invalid",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
		},
		{
			name:            "Invalid token state failure",
			hasTokenHeader:  true,
			hasCookieHeader: true,
			tokenState:      auth.JWTPreAuthorized,
			errMessage:      "token state is not supported",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
		},
		{
			name:            "Token validation failure",
			hasTokenHeader:  true,
			hasCookieHeader: true,
			tokenState:      auth.JWTAuthorized,
			errMessage:      "token check failed",
			tokenValidateFn: func() (*auth.Token, error) {
				return nil, auth.ErrInvalidToken("token check failed")
			},
		},
		{
			name:            "Successful request",
			hasTokenHeader:  true,
			hasCookieHeader: true,
			tokenState:      auth.JWTAuthorized,
			errMessage:      "",
			tokenValidateFn: func() (*auth.Token, error) {
				return &auth.Token{State: auth.JWTAuthorized}, nil
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tokenSvc := test.TokenService{
				ValidateFn: tc.tokenValidateFn,
			}

			w := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "", bytes.NewBuffer([]byte("{}")))
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			if tc.hasTokenHeader {
				r.Header.Set("AUTHORIZATION", "JWTTOKEN")
			}

			if tc.hasCookieHeader {
				cookie := http.Cookie{
					Name:     "CLIENTID",
					Value:    "client-id",
					MaxAge:   0,
					Secure:   true,
					HttpOnly: true,
					Raw:      "client-id",
				}
				r.AddCookie(&cookie)
			}

			h := AuthMiddleware(handler, &tokenSvc, tc.tokenState)
			v, err := h(w, r)

			domainErr := auth.DomainError(err)
			if domainErr != nil && domainErr.Message() != tc.errMessage {
				t.Errorf("error message does not match, want '%s' got '%s'",
					tc.errMessage, domainErr.Message())
			}

			if tc.errMessage == "" && err != nil {
				t.Error("expected nil error:", err)
			}

			b, ok := v.([]byte)
			if !ok && tc.errMessage == "" {
				t.Error("unexpected response type")
			}

			expectedResp := []byte(`{"foo":"bar"}`)
			if ok && !bytes.Equal(b, expectedResp) {
				t.Errorf("response does not match, want '%s' got '%s'",
					string(expectedResp), string(b))
			}
		})
	}
}
