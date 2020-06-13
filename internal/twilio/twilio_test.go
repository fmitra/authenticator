package twilio

import (
	"context"
	"net/http"
	"testing"

	"github.com/fmitra/authenticator/internal/test"
)

func TestTwilio_SMS(t *testing.T) {
	tt := []struct {
		name         string
		responseCode int
		hasError     bool
	}{
		{
			name:         "Success 201",
			responseCode: http.StatusCreated,
			hasError:     false,
		},
		{
			name:         "Invalid 200",
			responseCode: http.StatusOK,
			hasError:     true,
		},
		{
			name:         "Invalid 400",
			responseCode: http.StatusBadRequest,
			hasError:     true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			srv := test.Server(test.ServerResp{
				Path:       "/Accounts/accountSID/Messages.json",
				StatusCode: tc.responseCode,
			})
			defer srv.Close()

			ctx := context.Background()
			c := NewClient(WithConfig(Config{
				baseURL:    srv.URL,
				accountSID: "accountSID",
				authToken:  "authToken",
				smsSender:  "+15555555555",
			}))

			err := c.SMS(ctx, "+17777777777", "hello world")
			if err != nil && !tc.hasError {
				t.Error("expected nil error", err)
			}
			if err == nil && tc.hasError {
				t.Error("expected error, received nil")
			}
		})
	}
}
