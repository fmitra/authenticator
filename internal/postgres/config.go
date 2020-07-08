package postgres

import (
	"database/sql"
	"io"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
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

	c.createQueries()

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

// WithPassword configures the client with a PasswordService.
func WithPassword(p auth.PasswordService) ConfigOption {
	return func(c *Client) {
		c.userRepository.password = p
	}
}

// WithDB configures the client with a Postgres DB.
func WithDB(db *sql.DB) ConfigOption {
	return func(c *Client) {
		c.db = db
	}
}
