package msgrepo

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
)

func TestMsgRepo_Publish(t *testing.T) {
	tt := []struct {
		name     string
		msg      auth.Message
		hasError bool
	}{
		{
			name: "Does not publish after expiry",
			msg: auth.Message{
				ExpiresAt: time.Now().Add(time.Second * -5),
			},
			hasError: true,
		},
		{
			name: "Publishes to queue",
			msg: auth.Message{
				ExpiresAt: time.Now().Add(time.Second * 5),
			},
			hasError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc := NewService()
			err := svc.Publish(ctx, &tc.msg)
			if err != nil && !tc.hasError {
				t.Error("expected nil error, received", err)
			}
			if err == nil && tc.hasError {
				t.Error("expected error, not nil")
			}
		})
	}
}

func TestMsgRepo_Recent(t *testing.T) {
	msg := auth.Message{ExpiresAt: time.Now().Add(time.Second * 5)}
	ctx := context.Background()
	svc := NewService()
	err := svc.Publish(ctx, &msg)
	if err != nil {
		t.Error("failed to publish message", err)
	}

	msgc, errc := svc.Recent(ctx)
	select {
	case err = <-errc:
		t.Error("failed to retrieve message", err)
	case m := <-msgc:
		if !cmp.Equal(m, &msg) {
			t.Error("retrieved message does not match", cmp.Diff(m, &msg))
		}
	}
}
