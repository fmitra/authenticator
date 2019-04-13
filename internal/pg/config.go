package pg

import (
	"io"

	"github.com/go-kit/kit/log"
)

// NewClient returns a new Postgres client to manage repositories.
func NewClient(options ...ConfigOption) *Client {
	c := Client{
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

// WithEntropy configures the client with random entropy
// for generating ULIDs.
func WithEntropy(entropy io.Reader) ConfigOption {
	return func(c *Client) {
		c.entropy = entropy
	}
}
