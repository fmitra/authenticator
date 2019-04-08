package pg

import (
	"math/rand"
	"time"

	"github.com/go-kit/kit/log"
)

func NewClient(options ...ConfigOption) *Client {
	c := Client{
		rand:                   rand.New(rand.NewSource(time.Now().UnixNano())),
		logger:                 log.NewNopLogger(),
		LoginHistoryRepository: &LoginHistoryRepository{},
		DeviceRepository:       &DeviceRepository{},
		UserRepository:         &UserRepository{},
	}

	for _, opt := range options {
		opt(&c)
	}

	c.LoginHistoryRepository.client = &c
	c.DeviceRepository.client = &c
	c.UserRepository.client = &c

	return &c
}

// ConfigOption configures the Client.
type ConfigOption func(*Client)

// WithLogger configures the client with a Logger.
func WithLogger(l log.Logger) ConfigOption {
	return func(c *Client) {
		c.logger = l
	}
}
