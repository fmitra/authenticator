package msgconsumer

import (
	"testing"

	auth "github.com/fmitra/authenticator"
)

func TestMsgConsumer_WriteToQueue(t *testing.T) {
	t.Error("not implemented")
}

func TestMsgConsumer_ProcessMessage(t *testing.T) {
	tt := []struct {
		name        string
		smsLib      SMSer
		emailLib    Emailer
		messageRepo auth.MessageRepository
	}{
		{
			name:        "does not process if expired",
			smsLib:      nil,
			emailLib:    nil,
			messageRepo: nil,
		},
		{
			name:        "sends SMS",
			smsLib:      nil,
			emailLib:    nil,
			messageRepo: nil,
		},
		{
			name:        "sends email",
			smsLib:      nil,
			emailLib:    nil,
			messageRepo: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Error("not implemented")
		})
	}
}
