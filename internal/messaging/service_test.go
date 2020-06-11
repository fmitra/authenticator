package messaging

import (
	"testing"
)

func TestMessagingSvc_SMS(t *testing.T) {
	tt := []struct {
		name string
	}{
		{
			name: "Sends SMS",
		},
		{
			name: "Fails to send SMS",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("not implemented")
		})
	}
}
