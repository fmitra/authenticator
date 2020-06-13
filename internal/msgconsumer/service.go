// Package msgconsumer reads SMS/Email messages from Kafka.
package msgconsumer

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// Consumer reads a message stream from Kafka.
type Consumer interface {
	Run(ctx context.Context) error
}

// SMSer exposes an API to send SMS messages.
type SMSer interface {
	SMS(ctx context.Context, phoneNumber string, message string) error
}

// Emailer exposes an API to send email messages.
type Emailer interface {
	Email(ctx context.Context, email string, message string)
}

// Service consumes messages from a Kafka topic into a channel
// to be delivered in parallel through goroutines.
type service struct {
	logger       log.Logger
	smsLib       SMSer
	emailLib     Emailer
	emailLimit   string
	smsLimit     string
	totalWorkers int
	messageQueue chan *auth.Message
	messageRepo  auth.MessageRepository
}

// Run retrieves recent messages from the repository and passes
// them into a channel to be consumed by goroutines.
func (s *service) Run(ctx context.Context) error {
	msgc, errc := s.messageRepo.Recent(ctx)

	for {
		select {
		case msg, ok := <-msgc:
			if !ok {
				msgc = nil
				continue
			}
			s.messageQueue <- msg
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

// startWorkers starts a finite number of workers to deliver messages found
// in the message queue.
func (s *service) startWorkers() {
	for i := 0; i < s.totalWorkers; i++ {
		go func() {
			for msg := range s.messageQueue {
				s.processMessage(msg)
			}
		}()
	}
}

// processMessage delivers a message through email or SMS.
func (s *service) processMessage(m *auth.Message) {
}

func parseThrottle(t string) (int, string, error) {
	var duration string
	var limit int

	split := strings.Split(t, "/")
	if len(split) != 2 {
		return limit, duration, fmt.Errorf("throttle format requires limit and duration (e.g. 5/m)")
	}

	limit, err := strconv.Atoi(split[0])
	if err != nil {
		return limit, duration, fmt.Errorf("limit must be an integer")
	}

	duration = split[1]
	isDurationValid := map[string]bool{
		"m": true,
		"s": true,
		"h": true,
		"d": true,
	}
	if !isDurationValid[duration] {
		return limit, duration, fmt.Errorf("duration must be one of m, s, h, d")
	}

	return limit, duration, nil
}
