package signupapi

import (
	"bytes"
	"net/http"
	"testing"
)

func TestSignUpAPI_SignUpRequest(t *testing.T) {
	tt := []struct {
		name     string
		email    string
		phone    string
		request  []byte
		hasError bool
	}{
		{
			name:  "Is email attribute",
			email: "jane@example.com",
			phone: "",
			request: []byte(`{
				"password": "swordfish",
				"identity": "jane@example.com",
				"type": "email"
			}`),
			hasError: false,
		},
		{
			name:  "Is phone attribute",
			email: "",
			phone: "+15555555555",
			request: []byte(`{
				"password": "swordfish",
				"identity": "+15555555555",
				"type": "phone"
			}`),
			hasError: false,
		},
		{
			name:  "Is missing attribute",
			email: "",
			phone: "",
			request: []byte(`{
				"password": "swordfish",
				"identity": "janedoe",
				"type": "username"
			}`),
			hasError: true,
		},
		{
			name:  "Is invalid JSON",
			email: "",
			phone: "",
			request: []byte(`{
				"password": "swordfish",
				"identity": "jane@example.com",
				"type": "email",
			}`),
			hasError: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			req, err := decodeSignupRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if tc.hasError && req != nil {
				t.Error("expected nil response on error")
			}
			if !tc.hasError && req == nil {
				t.Error("expected decoded response, not nil")
			}

			if req == nil {
				return
			}

			user := req.ToUser()
			if user.Email.String != tc.email {
				t.Errorf("user phone does not match, want %s got %s",
					user.Email.String, tc.email)
			}
			if user.Phone.String != tc.phone {
				t.Errorf("user phone does not match, want %s got %s",
					user.Phone.String, tc.phone)
			}
		})
	}
}
