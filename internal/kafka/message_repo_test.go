package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/linkedin/goavro/v2"
	kafkaLib "github.com/segmentio/kafka-go"

	auth "github.com/fmitra/authenticator"
)

type readerMock struct {
	callCount   int
	readMessage func(ctx context.Context) (kafkaLib.Message, error)
}

func (r *readerMock) ReadMessage(ctx context.Context) (kafkaLib.Message, error) {
	r.callCount++
	return r.readMessage(ctx)
}

type writerMock struct {
	writeMessages func(ctx context.Context, msgs ...kafkaLib.Message) error
	callCount     int
}

func (w *writerMock) WriteMessages(ctx context.Context, msgs ...kafkaLib.Message) error {
	w.callCount++
	return w.writeMessages(ctx, msgs...)
}

func TestMessageRepo_Publish(t *testing.T) {
	tt := []struct {
		name   string
		fnMock func(ctx context.Context, msgs ...kafkaLib.Message) error
		err    error
	}{
		{
			name: "Publishes message",

			err: nil,
		},
		{
			name: "Fails to publish message",
			err:  errors.New("whoops"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			rMock := &readerMock{}
			wMock := &writerMock{
				writeMessages: func(ctx context.Context, msgs ...kafkaLib.Message) error {
					return tc.err
				},
			}
			c := Client{
				OTPReader: rMock,
				OTPWriter: wMock,
			}

			messageRepo, err := NewMessageRepository(&c)
			if err != nil {
				t.Error("failed to create message repository", err)
			}

			ctx := context.Background()
			err = messageRepo.Publish(ctx, &auth.Message{
				Delivery:  auth.Phone,
				Content:   "hello",
				Address:   "+1555555555",
				ExpiresAt: time.Now(),
			})
			if !errors.Is(err, tc.err) {
				t.Errorf("response does not match, want %v got %v", tc.err, err)
			}
			if wMock.callCount != 1 {
				t.Errorf("expected %v calls, received %v", 1, wMock.callCount)
			}
		})
	}
}

func TestMessageRepo_Recent(t *testing.T) {
	var msg *auth.Message
	var err error

	codec, err := goavro.NewCodec(MessageSchema)
	if err != nil {
		t.Error("failed to create codec", err)
	}

	expiry := time.Now()
	nativeMsg := map[string]interface{}{
		"delivery":   "phone",
		"content":    "Hello world",
		"address":    "Park Ave",
		"expires_at": expiry.Truncate(time.Microsecond),
	}
	b, err := codec.BinaryFromNative(nil, nativeMsg)
	if err != nil {
		t.Error("failed to encode message", err)
	}

	readerMock := readerMock{
		readMessage: func(ctx context.Context) (kafkaLib.Message, error) {
			return kafkaLib.Message{Value: b}, nil
		},
	}

	c := Client{
		OTPReader: &readerMock,
		OTPWriter: &writerMock{},
	}
	messageRepo, err := NewMessageRepository(&c)
	if err != nil {
		t.Error("failed to create message repository", err)
	}

	// Set a timeout otherwise the repo will stream from Kafka indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgc, errc := messageRepo.Recent(ctx)

	msg = <-msgc
	err = <-errc
	if err.Error() != "context deadline exceeded" {
		t.Error("expected timeout error", err)
	}

	expectedMsg := &auth.Message{
		Delivery:  auth.Phone,
		Content:   "Hello world",
		Address:   "Park Ave",
		ExpiresAt: expiry,
	}
	if !cmp.Equal(msg, expectedMsg) {
		t.Error("message response does not match", cmp.Diff(msg, expectedMsg))
	}

	if readerMock.callCount == 0 {
		t.Errorf("expected calls, received %v", readerMock.callCount)
	}
}
