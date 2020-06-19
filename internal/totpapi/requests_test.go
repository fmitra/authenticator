package totpapi

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTOTPAPI_TOTPRequest(t *testing.T) {
	tt := []struct {
		name     string
		code     string
		request  []byte
		hasError bool
	}{
		{
			name:     "Code received as string",
			code:     "123456",
			request:  []byte(`{"code": "123456"}`),
			hasError: false,
		},
		{
			name:     "Code received as number",
			code:     "123456",
			request:  []byte(`{"code": 123456}`),
			hasError: true,
		},
		{
			name:     "Empty code",
			code:     "",
			request:  []byte(`{"code": ""}`),
			hasError: true,
		},
		{
			name:     "Invalid request format",
			code:     "",
			request:  []byte(`{}`),
			hasError: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "", bytes.NewBuffer(tc.request))
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			req, err := decodeTOTPRequest(r)
			if !tc.hasError && err != nil {
				t.Error("expected nil error:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}
			if req != nil && !cmp.Equal(req.Code, tc.code) {
				t.Error(cmp.Diff(req.Code, tc.code))
			}
		})
	}
}
