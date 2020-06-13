package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/linkedin/goavro/v2"
	kafkaLib "github.com/segmentio/kafka-go"

	auth "github.com/fmitra/authenticator"
)

// MessageRepository allows us to read and write to an OTP
// Kafka topic.
type MessageRepository struct {
	reader *kafkaLib.Reader
	writer *kafkaLib.Writer
	codec  *goavro.Codec
}

// NewMessageRepository returns a new implementation of auth.MessageRepository.
func NewMessageRepository(client *Client) (auth.MessageRepository, error) {
	codec, err := goavro.NewCodec(MessageSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to create message codec: %w", err)
	}

	return &MessageRepository{
		reader: client.OTPReader,
		writer: client.OTPWriter,
		codec:  codec,
	}, nil
}

// Publish writes a message to topic `authenticator.messages.otp`.
func (r *MessageRepository) Publish(ctx context.Context, msg *auth.Message) error {
	nativeMsg := map[string]interface{}{
		"delivery":   msg.Delivery,
		"content":    msg.Content,
		"address":    msg.Address,
		"expires_at": msg.ExpiresAt.Truncate(time.Microsecond),
	}

	b, err := r.codec.BinaryFromNative(nil, nativeMsg)
	if err != nil {
		return fmt.Errorf("failed to convert msg to binary: %w", err)
	}

	return r.writer.WriteMessages(ctx, kafkaLib.Message{
		Value: b,
	})
}

// Recent retrieves messages recently written to `authenticator.messages.otp`.
func (r *MessageRepository) Recent(ctx context.Context) (<-chan *auth.Message, <-chan error) {
	errc := make(chan error, 1)
	msgc := make(chan *auth.Message)

	go func() {
		defer close(errc)
		defer close(msgc)

		for {
			kafkaMsg, err := r.reader.ReadMessage(ctx)
			if err != nil {
				errc <- fmt.Errorf("failed to read otp: %w", err)
				break
			}

			decoded, _, err := r.codec.NativeFromBinary(kafkaMsg.Value)
			if err != nil {
				errc <- fmt.Errorf("failed to unmarshal message: %w", err)
				return
			}

			dataMap, ok := decoded.(map[string]interface{})
			if !ok {
				errc <- fmt.Errorf("failed to read message: %w", err)
				return
			}

			var msg auth.Message
			msg.ExpiresAt = dataMap["expires_at"].(time.Time)
			msg.Address = dataMap["address"].(string)
			msg.Content = dataMap["content"].(string)
			msg.Delivery = auth.DeliveryMethod(dataMap["delivery"].(string))

			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case msgc <- &msg:
				continue
			}
		}
	}()

	return msgc, errc
}
