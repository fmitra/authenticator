package msgpublisher

import (
	"context"
	"fmt"
	"testing"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestMsgPublisher_Send(t *testing.T) {
	tt := []struct {
		name           string
		address        string
		deliveryMethod auth.DeliveryMethod
		publishMock    func(ctx context.Context, msg *auth.Message) error
		isFailed       bool
	}{
		{
			name:           "Sends SMS",
			deliveryMethod: auth.Phone,
			address:        "+639455189172",
			isFailed:       false,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				if msg.Delivery != auth.Phone {
					t.Errorf("incorrect delivery method: want %s, got %s", auth.Phone, msg.Delivery)
				}
				return nil
			},
		},
		{
			name:           "Fails to send SMS",
			deliveryMethod: auth.Phone,
			address:        "94867353",
			isFailed:       true,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				return fmt.Errorf("whoops")
			},
		},
		{
			name:           "Sends email",
			deliveryMethod: auth.Email,
			address:        "jane@example.com",
			isFailed:       false,
			publishMock: func(ctx context.Context, msg *auth.Message) error {
				if msg.Delivery != auth.Email {
					t.Errorf("incorrect delivery method: want %s, got %s", auth.Email, msg.Delivery)
				}
				return nil
			},
		},
		{
			name:           "Fails to send email",
			deliveryMethod: auth.Email,
			address:        "jane@example.com",
			isFailed:       true,
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
			err := publisherSvc.Send(ctx, "Here's your code: 111", tc.address, tc.deliveryMethod)
			if err != nil && !tc.isFailed {
				t.Error("expected nil error, received:", err)
			}
			if err == nil && tc.isFailed {
				t.Error("expected error, received nil")
			}
		})
	}
}
