package contactapi

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
)

func TestContactAPI_CheckAddressRequest(t *testing.T) {
	tt := []struct {
		name           string
		request        []byte
		address        string
		deliveryMethod auth.DeliveryMethod
		hasError       bool
	}{
		{
			name:           "Invaild request format",
			request:        []byte(`{}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Missing deliveryMethod",
			request:        []byte(`{"address": "jane@example.com", "deliveryMethod": ""}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Invalid deliveryMethod",
			request:        []byte(`{"address": "jane@example.com", "deliveryMethod": "unsupported"}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Missing address",
			request:        []byte(`{"address": "", "deliveryMethod": "email"}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Valid request",
			request:        []byte(`{"address": "jane@example.com", "deliveryMethod": "email"}`),
			address:        "jane@example.com",
			deliveryMethod: auth.Email,
			hasError:       false,
		},
		{
			name:           "Invalid email address format",
			request:        []byte(`{"address": "not-a-real-email", "deliveryMethod": "email"}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Invalid phone number format",
			request:        []byte(`{"address": "not-a-real-phone", "deliveryMethod": "phone"}`),
			address:        "",
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock reqeust:", err)
			}

			req, err := decodeDeliveryRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if req != nil && !cmp.Equal(req.DeliveryMethod, tc.deliveryMethod) {
				t.Error(cmp.Diff(req.DeliveryMethod, tc.deliveryMethod))
			}
			if req != nil && !cmp.Equal(req.Address, tc.address) {
				t.Error(cmp.Diff(req.Address, tc.address))
			}
		})
	}
}

func TestContactAPI_VerifyRequest(t *testing.T) {
	tt := []struct {
		request      []byte
		name         string
		code         string
		isOTPEnabled bool
		hasError     bool
	}{
		{
			name:         "Invaild request format",
			request:      []byte(`{}`),
			isOTPEnabled: true,
			code:         "",
			hasError:     true,
		},
		{
			name:         "Missing code",
			request:      []byte(`{"code": ""}`),
			isOTPEnabled: true,
			code:         "",
			hasError:     true,
		},
		{
			name:         "Enabled by default",
			request:      []byte(`{"code": "123456"}`),
			isOTPEnabled: true,
			code:         "123456",
			hasError:     false,
		},
		{
			name:         "Disabled optionally",
			request:      []byte(`{"code": "123456", "isDisabled": true}`),
			isOTPEnabled: false,
			code:         "123456",
			hasError:     false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock reqeust:", err)
			}

			req, err := decodeVerifyRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if req != nil && !cmp.Equal(req.Code, tc.code) {
				t.Error(cmp.Diff(req.Code, tc.code))
			}
			if req != nil && !cmp.Equal(req.IsOTPEnabled, tc.isOTPEnabled) {
				t.Error(cmp.Diff(req.IsOTPEnabled, tc.isOTPEnabled))
			}
		})
	}
}

func TestContactAPI_DeactivateRequest(t *testing.T) {
	tt := []struct {
		name           string
		request        []byte
		deliveryMethod auth.DeliveryMethod
		hasError       bool
	}{
		{
			name:           "Invaild request format",
			request:        []byte(`{}`),
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Missing delivery method",
			request:        []byte(`{"deliveryMethod": ""}`),
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Invalid delivery method",
			request:        []byte(`{"deliveryMethod": "unsupported"}`),
			deliveryMethod: auth.DeliveryMethod(""),
			hasError:       true,
		},
		{
			name:           "Valid delivery method",
			request:        []byte(`{"deliveryMethod": "phone"}`),
			deliveryMethod: auth.Phone,
			hasError:       false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock reqeust:", err)
			}

			req, err := decodeDeactivateRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if req != nil && !cmp.Equal(req.DeliveryMethod, tc.deliveryMethod) {
				t.Error(cmp.Diff(req.DeliveryMethod, tc.deliveryMethod))
			}
		})
	}
}
