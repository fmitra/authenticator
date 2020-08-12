package twilio

import (
	"strings"

	auth "github.com/fmitra/authenticator"
)

// defaultBaseURL sets the default API version for all Twilio requests.
const defaultBaseURL = "https://api.twilio.com/2010-04-01"

// Config holds configuration options for Twilio.
type Config struct {
	baseURL    string
	accountSID string
	authToken  string
	smsSender  string
}

// ConfigOption configures the service.
type ConfigOption func(*client)

// NewClient returns a Twilio client.
func NewClient(configuration ConfigOption) auth.SMSer {
	c := client{}
	configuration(&c)
	return &c
}

// WithConfig configures the service with a Config.
func WithConfig(config Config) ConfigOption {
	return func(c *client) {
		c.accountSID = config.accountSID
		c.authToken = config.authToken
		c.baseURL = strings.TrimSuffix(config.baseURL, "/")
		c.smsSender = config.smsSender
	}
}

// WithDefaults configures a Twilio client with a user's
// account SID and authentication token and configures all other
// values to default.
func WithDefaults(accountSID, authToken, smsSender string) ConfigOption {
	return func(c *client) {
		c.accountSID = accountSID
		c.authToken = authToken
		c.baseURL = defaultBaseURL
		c.smsSender = smsSender
	}
}
