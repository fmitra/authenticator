// Package kafka contains repositories backed by Kafka.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"

	kafkaLib "github.com/segmentio/kafka-go"

	auth "github.com/fmitra/authenticator"
)

// MessageRepository allows us to read and write to an OTP
// Kafka topic.
type MessageRepository struct {
	reader *kafkaLib.Reader
	writer *kafkaLib.Writer
}

// NewMessageRepository returns a new implementation of auth.MessageRepository.
func NewMessageRepository(client *Client) auth.MessageRepository {
	return &MessageRepository{
		reader: client.OTPReader,
		writer: client.OTPWriter,
	}
}

// Publish writes a message to topic `authenticator.messages.otp`.
func (r *MessageRepository) Publish(ctx context.Context, msg *auth.Message) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
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

			var msg auth.Message
			{
				err = json.Unmarshal(kafkaMsg.Value, &msg)
				if err != nil {
					errc <- fmt.Errorf("failed to  unmarshal message: %w", err)
					return
				}
			}

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
