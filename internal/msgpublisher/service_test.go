package msgpublisher

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestMsgPublisher_Send(t *testing.T) {
	tt := []struct {
		name        string
		user        auth.User
		publishMock func(ctx context.Context, msg *auth.Message) error
		isFailed    bool
	}{
		{
			name: "Sends SMS",
			user: auth.User{
				Phone: sql.NullString{
					String: "94867353",
					Valid:  true,
				},
				Email: sql.NullString{},
			},
			isFailed: false,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				if msg.Delivery != auth.Phone {
					t.Errorf("incorrect delivery method: want %s, got %s", auth.Phone, msg.Delivery)
				}
				return nil
			},
		},
		{
			name: "Fails to send SMS",
			user: auth.User{
				Phone: sql.NullString{
					String: "94867353",
					Valid:  true,
				},
				Email: sql.NullString{},
			},
			isFailed: true,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				return fmt.Errorf("whoops")
			},
		},
		{
			name: "Sends email",
			user: auth.User{
				Phone: sql.NullString{},
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			isFailed: false,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				if msg.Delivery != auth.Email {
					t.Errorf("incorrect delivery method: want %s, got %s", auth.Email, msg.Delivery)
				}
				return nil
			},
		},
		{
			name: "Fails to send email",
			user: auth.User{
				Phone: sql.NullString{},
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			isFailed: true,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				return fmt.Errorf("whoops")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			messageRepo := test.MessageRepository{
				PublishFn: tc.publishMock,
			}

			ctx := context.Background()
			publisherSvc := NewService(&messageRepo)
			err := publisherSvc.Send(ctx, &tc.user, "Here's your code: 111")
			if err != nil && !tc.isFailed {
				t.Error("expected nil error, received:", err)
			}
			if err == nil && tc.isFailed {
				t.Error("expected error, received nil")
			}
		})
	}
}
