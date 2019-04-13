package pg

import (
	"io"

	"github.com/go-kit/kit/log"
)

// NewClient returns a new Postgres client to manage repositories.
func NewClient(options ...ConfigOption) *Client {
	c := Client{
		logger:                 log.NewNopLogger(),
		loginHistoryRepository: &LoginHistoryRepository{},
		deviceRepository:       &DeviceRepository{},
		userRepository:         &UserRepository{},
	}

	for _, opt := range options {
		opt(&c)
	}

	// Each repository has an embedded client to ensure they
	// use the same connection and are able to share transactions.
	c.loginHistoryRepository.client = &c
	c.deviceRepository.client = &c
	c.userRepository.client = &c

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
