package msgpublisher

import (
	"testing"
)

func TestMessagingSvc_Send(t *testing.T) {
	tt := []struct {
		name string
	}{
		{
			name: "Sends SMS",
		},
		{
			name: "Fails to send SMS",
		},
		{
			name: "Sends email",
		},
		{
			name: "Fails to send email",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("not implemented")
		})
	}
}
