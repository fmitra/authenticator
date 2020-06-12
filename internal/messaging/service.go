package messaging

import (
	"context"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// SMSer exposes an API to send SMS messages.
type SMSer interface {
	SMS(ctx context.Context, phoneNumber string, message string) error
}

// Emailer exposes an API to send email messages.
type Emailer interface {
	Email(ctx context.Context, email string, message string)
}

// Kafka is an interface to consume and publish to Kafka.
type Kafka interface {
	Consume(ctx context.Context) (<-chan string, <-chan error)
	Publish(ctx context.Context, msg string) error
}

// service is an implementation of auth.MessagingService.
// It uses the Twilio API to send messages.
type service struct {
	logger       log.Logger
	smsLib       SMSer
	emailLib     Emailer
	totalWorkers int
	emailLimit   string
	smsLimit     string
	messageQueue chan func()
	kafka        Kafka
}

// Send sends a message to a User. Behind the scenes, it publishes a message
// to a Kafka topic with all the relevant user details for delivery (e.g. phone/email).
func (s *service) Send(ctx context.Context, user *auth.User, message string) error {
	// TODO Add an expiry time to the message
	if err := s.kafka.Publish(ctx, message); err != nil {
		return err
	}

	return nil
}

// consume reads messages from a Kafka topic and sends it into a messaging queue
// channel.
func (s *service) consume(ctx context.Context) error {
	msgc, errc := s.kafka.Consume(ctx)

	for {
		select {
		case _, ok := <-msgc:
			if !ok {
				msgc = nil
				continue
			}
			s.messageQueue <- func() {
				// TODO Send via SMS or Email
				// TODO Consider splitting the service into messagepublisher
				// and messageconsumer. The publisher implements the MessageService
				// interface and the consumer manages delivery libraries and
				// message queues.
				// TODO Don't send a function to the queue. Create some data type
				// to represent the message and add an expiry time for sending
				// (e.g. skip delivery after 5min)
			}
		case err := <-errc:
			if err != nil {
				return err
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// sendMessages starts a finite number of workers to deliver messages found
// in the message queue.
func (s *service) processQueue() {
	for i := 0; i < s.totalWorkers; i++ {
		go func() {
			for message := range s.messageQueue {
				// TODO throttle our requests. Set a redis cache key based on the
				// second of the day with a 2 second expiry and increment it
				// for each message being processed. Before processing, check the key
				// value and if its over the configured processing limit, wait
				// 1 second.
				// TODO message queue will hold a struct instead of a function.
				// We should determine whether to use email or SMS here and apply the
				// relevant throttle
				message()
			}
		}()
	}
}
