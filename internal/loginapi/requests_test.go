package loginapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestLoginAPI_LoginRequestAttribute(t *testing.T) {
	tt := []struct {
		name     string
		userAttr string
		request  []byte
	}{
		{
			name:     "Is email attribute",
			userAttr: "Email",
			request: []byte(`{
				"password": "swordfish",
				"identity": "jane@example.com",
				"type": "email"
			}`),
		},
		{
			name:     "Is phone attribute",
			userAttr: "Phone",
			request: []byte(`{
				"password": "swordfish",
				"identity": "+1555555555",
				"type": "phone"
			}`),
		},
		{
			name:     "Is missing attribute",
			userAttr: "",
			request: []byte(`{
				"password": "swordfish",
				"identity": "janedoe",
				"type": "username"
			}`),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var r loginRequest
			err := json.Unmarshal(tc.request, &r)
			if err != nil {
				t.Fatal("failed to unmarshal data:", err)
			}

			if tc.userAttr != r.UserAttribute() {
				t.Errorf("attribute values do not match, want %s got %s",
					tc.userAttr, r.UserAttribute())
			}
		})
	}
}

func TestLoginAPI_LoginRequestDecode(t *testing.T) {
	tt := []struct {
		name     string
		request  []byte
		hasError bool
	}{
		{
			name: "Invalid json error",
			request: []byte(`{
				"password": "swordfish",
				"identity": "+15555555555",
				"type": "phone",
			}`),
			hasError: true,
		},
		{
			name: "Invalid attribute error",
			request: []byte(`{
				"password": "swordfish",
				"identity": "janedoe",
				"type": "username",
			}`),
			hasError: true,
		},
		{
			name: "Valid request",
			request: []byte(`{
				"password": "swordfish",
				"identity": "+15555555555",
				"type": "phone"
			}`),
			hasError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			req, err := decodeLoginRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if tc.hasError && req != nil {
				t.Error("expected nil response on error")
			}
			if reflect.TypeOf(req).String() != "*loginapi.loginRequest" {
				t.Errorf("incorrect type, want *loginapi.loginRequest, got %s",
					reflect.TypeOf(req).String())
			}
		})
	}
}

func TestLoginAPI_VerifyCodeRequest(t *testing.T) {
	tt := []struct {
		name     string
		request  []byte
		hasError bool
	}{
		{
			name: "Invalid json error",
			request: []byte(`{
				"code": "123456",
			}`),
			hasError: true,
		},
		{
			name: "Valid request",
			request: []byte(`{
				"code": "123456"
			}`),
			hasError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			req, err := decodeVerifyCodeRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if tc.hasError && req != nil {
				t.Error("expected nil response on error")
			}
			if reflect.TypeOf(req).String() != "*loginapi.verifyCodeRequest" {
				t.Errorf("incorrect type, want *loginapi.verifyCodeRequest, got %s",
					reflect.TypeOf(req).String())
			}
		})
	}

}
