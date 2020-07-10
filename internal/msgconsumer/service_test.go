package msgconsumer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

type emailMock struct {
	callCount int
	EmailFn   func(ctx context.Context, email, message string) error
}

type smsMock struct {
	callCount int
	SMSFn     func(ctx context.Context, phoneNumber, message string) error
}

func (m *emailMock) Email(ctx context.Context, email, message string) error {
	m.callCount++
	if m.EmailFn != nil {
		return m.EmailFn(ctx, email, message)
	}
	return nil
}

func (m *smsMock) SMS(ctx context.Context, phoneNumber, message string) error {
	m.callCount++
	if m.SMSFn != nil {
		return m.SMSFn(ctx, phoneNumber, message)
	}
	return nil
}

func TestMsgConsumer_ProcessMessage(t *testing.T) {
	tt := []struct {
		name         string
		messageFn    func(ch chan<- bool) func(ctx context.Context, addr, message string) error
		publishFn    func(ch chan<- bool) func(ctx context.Context, msg *auth.Message) error
		recentFn     func(ctx context.Context) (<-chan *auth.Message, <-chan error)
		publishCount int
		smsCount     int
		emailCount   int
	}{
		{
			name:         "Does not process if expired",
			publishCount: 0,
			smsCount:     0,
			emailCount:   0,
			messageFn: func(ch chan<- bool) func(ctx context.Context, addr, message string) error {
				return func(ctx context.Context, addr, message string) error {
					ch <- true
					return nil
				}
			},
			recentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
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
			publishFn: func(ch chan<- bool) func(ctx context.Context, msg *auth.Message) error {
				return func(ctx context.Context, msg *auth.Message) error {
					ch <- true
					return nil
				}
			},
		},
		{
			name:         "Sends SMS",
			publishCount: 0,
			smsCount:     1,
			emailCount:   0,
			messageFn: func(ch chan<- bool) func(ctx context.Context, addr, message string) error {
				return func(ctx context.Context, addr, message string) error {
					ch <- true
					return nil
				}
			},
			recentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
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
			publishFn: func(ch chan<- bool) func(ctx context.Context, msg *auth.Message) error {
				return func(ctx context.Context, msg *auth.Message) error {
					ch <- true
					return nil
				}
			},
		},
		{
			name:         "Sends email",
			publishCount: 0,
			smsCount:     0,
			emailCount:   1,
			messageFn: func(ch chan<- bool) func(ctx context.Context, addr, message string) error {
				return func(ctx context.Context, addr, message string) error {
					ch <- true
					return nil
				}
			},
			recentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
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
			publishFn: func(ch chan<- bool) func(ctx context.Context, msg *auth.Message) error {
				return func(ctx context.Context, msg *auth.Message) error {
					ch <- true
					return nil
				}
			},
		},
		{
			name:         "Publishes on failure",
			publishCount: 1,
			smsCount:     0,
			emailCount:   1,
			messageFn: func(ch chan<- bool) func(ctx context.Context, addr, message string) error {
				return func(ctx context.Context, addr, message string) error {
					ch <- true
					return fmt.Errorf("whoops")
				}
			},
			recentFn: func(ctx context.Context) (<-chan *auth.Message, <-chan error) {
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
			publishFn: func(ch chan<- bool) func(ctx context.Context, msg *auth.Message) error {
				return func(ctx context.Context, msg *auth.Message) error {
					ch <- true
					return nil
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			smsChan := make(chan bool)
			emailChan := make(chan bool)
			publishChan := make(chan bool)

			defer close(smsChan)
			defer close(emailChan)
			defer close(publishChan)

			ctx := context.Background()
			smsLib := smsMock{
				SMSFn: tc.messageFn(smsChan),
			}
			emailLib := emailMock{
				EmailFn: tc.messageFn(emailChan),
			}
			messageRepo := test.MessageRepository{
				PublishFn: tc.publishFn(publishChan),
				RecentFn:  tc.recentFn,
			}
			consumerSvc := NewService(&messageRepo, &smsLib, &emailLib)

			if err := consumerSvc.Run(ctx); err != nil {
				t.Error("expected nil error, received:", err)
			}

			select {
			case <-emailChan:
				if !cmp.Equal(tc.emailCount, emailLib.callCount) {
					t.Error("incorrect calls to email library", cmp.Diff(
						tc.emailCount, emailLib.callCount,
					))
				}
			case <-smsChan:
				if !cmp.Equal(tc.smsCount, smsLib.callCount) {
					t.Error("incorrect calls to SMS library", cmp.Diff(
						tc.smsCount, smsLib.callCount,
					))
				}
			default:
				if tc.emailCount != 0 && tc.smsCount != 0 {
					t.Error("no messages processed")
				}
			}

			select {
			case <-publishChan:
				if !cmp.Equal(tc.publishCount, messageRepo.Calls.Publish) {
					t.Error("incorrect calls to MessageRepository.Publish", cmp.Diff(
						tc.publishCount, messageRepo.Calls.Publish,
					))
				}
			case <-time.After(time.Second):
				if tc.publishCount != 0 {
					t.Error("no messages published")
				}
			}
		})
	}
}
