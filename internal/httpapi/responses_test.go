package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestHTTPAPI_JSONResponse(t *testing.T) {
	tt := []struct {
		name      string
		response  interface{}
		result    string
		statusIn  int
		statusOut int
	}{
		{
			name:      "Handles nil response",
			response:  nil,
			result:    `{}`,
			statusIn:  http.StatusOK,
			statusOut: http.StatusOK,
		},
		{
			name:      "Handles byte response",
			response:  []byte(`{"foo": "bar"}`),
			result:    `{"foo": "bar"}`,
			statusIn:  http.StatusOK,
			statusOut: http.StatusOK,
		},
		{
			name: "Handles struct response",
			response: struct {
				Name string `json:"name"`
			}{
				Name: "Jane",
			},
			result:    `{"name":"Jane"}`,
			statusIn:  http.StatusOK,
			statusOut: http.StatusOK,
		},
		{
			name:      "Handles marshal error",
			response:  func() {},
			result:    "An internal error occurred",
			statusIn:  http.StatusOK,
			statusOut: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			JSONResponse(w, tc.response, tc.statusIn)

			resp := w.Result()
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatal("failed to read body:", err)
			}

			if resp.StatusCode != tc.statusOut {
				t.Errorf("incorrect status code returned, want %v got %v",
					tc.statusOut, resp.StatusCode)
			}
			if tc.statusOut == http.StatusOK && string(body) != tc.result {
				t.Errorf("incorrect response, want '%s' got '%s'",
					tc.result, string(body))
			}

			err = test.ValidateErrMessage(tc.result, bytes.NewBuffer(body))
			if tc.statusOut != http.StatusOK && err != nil {
				t.Error("error message does not match", err)
			}
		})
	}
}

func TestHTTPAPI_ErrorResponse(t *testing.T) {
	tt := []struct {
		name    string
		err     error
		message string
	}{
		{
			name:    "Handles auth error",
			err:     auth.ErrInvalidToken("token is invalid"),
			message: "token is invalid",
		},
		{
			name:    "Handles default domain error",
			err:     auth.ErrBadRequest("something bad happened"),
			message: "something bad happened",
		},
		{
			name:    "Handles internal error",
			err:     fmt.Errorf("whoops"),
			message: "An internal error occurred",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ErrorResponse(w, tc.err)

			resp := w.Result()
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatal("failed to read body:", err)
			}

			err = test.ValidateErrMessage(tc.message, bytes.NewBuffer(body))
			if err != nil {
				t.Error("Error messsage does not match:", err)
			}
		})
	}
}

func TestHTTPAPI_UserID(t *testing.T) {
	r, err := http.NewRequest("GET", "", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		t.Fatal("failed to create mock request:", err)
	}

	ctx := r.Context()
	newCtx := context.WithValue(ctx, userIDContextKey, "userID")
	r = r.WithContext(newCtx)

	userID := GetUserID(r)
	if userID != "userID" {
		t.Errorf("incorrect userID, want userID got '%s'", userID)
	}
}

func TestHTTPAPI_Token(t *testing.T) {
	r, err := http.NewRequest("GET", "", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		t.Fatal("failed to create mock request:", err)
	}

	ctx := r.Context()
	newCtx := context.WithValue(ctx, tokenContextKey, &auth.Token{ClientID: "clientID"})
	r = r.WithContext(newCtx)

	token := GetToken(r)
	if token == nil {
		t.Fatal("no token set on context")
	}
	if token.ClientID != "clientID" {
		t.Errorf("incorrect clientID, want clientID got '%s'", token.ClientID)
	}
}
