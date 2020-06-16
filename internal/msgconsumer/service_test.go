package msgconsumer

import (
	"context"
	"fmt"
	"testing"
	"time"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

type emailMock struct {
	callCount int
	EmailFn   func(ctx context.Context, email string, message string) error
}

type smsMock struct {
	callCount int
	SMSFn     func(ctx context.Context, phoneNumber string, message string) error
}

func (m *emailMock) Email(ctx context.Context, email string, message string) error {
	m.callCount++
	if m.EmailFn != nil {
		return m.EmailFn(ctx, email, message)
	}
	return nil
}

func (m *smsMock) SMS(ctx context.Context, phoneNumber string, message string) error {
	m.callCount++
	if m.SMSFn != nil {
		return m.SMSFn(ctx, phoneNumber, message)
	}
	return nil
}

func TestMsgConsumer_ProcessMessage(t *testing.T) {
	tt := []struct {
		name         string
		smsLib       smsMock
		emailLib     emailMock
		messageRepo  test.MessageRepository
		publishCount int
		smsCount     int
		emailCount   int
	}{
		{
			name:         "Does not process if expired",
			smsLib:       smsMock{},
			emailLib:     emailMock{},
			publishCount: 0,
			smsCount:     0,
			emailCount:   0,
			messageRepo: test.MessageRepository{
				RecentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
					errc := make(chan error, 1)
					msgc := make(chan *auth.Message)
					go func() {
						defer close(errc)
						defer close(msgc)
						msg := &auth.Message{
							Delivery: auth.Email,
							// Expires in the past
							ExpiresAt: time.Now().Add(time.Duration(-1) * time.Minute),
						}
						msgc <- msg
					}()
					return msgc, errc
				},
			},
		},
		{
			name:         "Sends SMS",
			smsLib:       smsMock{},
			emailLib:     emailMock{},
			publishCount: 0,
			smsCount:     1,
			emailCount:   0,
			messageRepo: test.MessageRepository{
				RecentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
					errc := make(chan error, 1)
					msgc := make(chan *auth.Message)
					go func() {
						defer close(errc)
						defer close(msgc)
						msg := &auth.Message{
							Delivery:  auth.Phone,
							ExpiresAt: time.Now().Add(time.Minute),
						}
						msgc <- msg
					}()
					return msgc, errc
				},
			},
		},
		{
			name:         "Sends email",
			smsLib:       smsMock{},
			emailLib:     emailMock{},
			publishCount: 0,
			smsCount:     0,
			emailCount:   1,
			messageRepo: test.MessageRepository{
				RecentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
					errc := make(chan error, 1)
					msgc := make(chan *auth.Message)
					go func() {
						defer close(errc)
						defer close(msgc)
						msg := &auth.Message{
							Delivery:  auth.Email,
							ExpiresAt: time.Now().Add(time.Minute),
						}
						msgc <- msg
					}()
					return msgc, errc
				},
			},
		},
		{
			name:   "Publishes on failure",
			smsLib: smsMock{},
			emailLib: emailMock{
				EmailFn: func(ctx context.Context, email string, message string) error {
					return fmt.Errorf("whoops")
				},
			},
			publishCount: 1,
			smsCount:     0,
			emailCount:   1,
			messageRepo: test.MessageRepository{
				RecentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
					errc := make(chan error, 1)
					msgc := make(chan *auth.Message)
					go func() {
						defer close(errc)
						defer close(msgc)
						msg := &auth.Message{
							Delivery:  auth.Email,
							ExpiresAt: time.Now().Add(time.Minute),
						}
						msgc <- msg
					}()
					return msgc, errc
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			consumerSvc, err := NewService(ctx, &tc.messageRepo, &tc.smsLib, &tc.emailLib)
			if err != nil {
				t.Error("expected nil error, received:", err)
			}

			if err := consumerSvc.Run(ctx); err != nil {
				t.Error("expected nil error, received:", err)
			}

			time.Sleep(time.Second)

			if tc.messageRepo.Calls.Publish != tc.publishCount {
				t.Errorf("incorrect call count to Publish: want %v, got %v",
					tc.publishCount, tc.messageRepo.Calls.Publish,
				)
			}

			if tc.smsLib.callCount != tc.smsCount {
				t.Errorf("incorrect call count to SMS lib: want %v, got %v",
					tc.smsCount, tc.smsLib.callCount,
				)
			}

			if tc.emailLib.callCount != tc.emailCount {
				t.Errorf("incorrect call count to Email lib: want %v, got %v",
					tc.emailCount, tc.emailLib.callCount,
				)
			}
		})
	}
}
