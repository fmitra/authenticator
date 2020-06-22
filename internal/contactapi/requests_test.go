package contactapi

import (
	"testing"
	"bytes"
	"net/http"

	"github.com/google/go-cmp/cmp"
)

func TestContactAPI_CheckAddressRequest(t *testing.T) {
	tt := []struct {
		name string
		request []byte
		address string
		deliveryMethod string
		hasError bool
	}{
		{
			name: "Invaild request format",
			request: []byte(`{}`),
			address: "",
			deliveryMethod: "",
			hasError: true,
		},
		{
			name: "Missing delivery_type",
			request: []byte(`{"address": "jane@example.com", "delivery_type": ""}`),
			address: "",
			deliveryMethod: "",
			hasError: true,
		},
		{
			name: "Invalid delivery_type",
			request: []byte(`{"address": "jane@example.com", "delivery_type": "unsupported"}`),
			address: "",
			deliveryMethod: "",
			hasError: true,
		},
		{
			name: "Missing address",
			request: []byte(`{"address": "", "delivery_type": "email"}`),
			address: "",
			deliveryMethod: "",
			hasError: true,
		},
		{
			name: "Valid request",
			request: []byte(`{"address": "jane@example.com", "delivery_type": "email"}`),
			address: "jane@example.com",
			deliveryMethod: "email",
			hasError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock reqeust:", err)
			}

			req, err := decodeCheckAddressRequest(r)
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
