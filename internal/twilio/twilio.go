package twilio

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

// Twilio exposes Twilio's REST API.
type Twilio interface {
	// SMS sends an SMS message to a phone number.
	SMS(ctx context.Context, phoneNumber string, message string) error
}

// client is a consumer of the Twilio API.
type client struct {
	baseURL    string
	accountSID string
	authToken  string
	smsSender  string
}

// SMS sends an SMS message to a phone number.
func (c *client) SMS(ctx context.Context, phoneNumber string, message string) error {
	url := fmt.Sprintf(
		"%s/Accounts/%s/Messages.json",
		c.baseURL,
		c.accountSID,
	)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	smsTemplate := map[string]string{
		"To":   phoneNumber,
		"From": c.smsSender,
		"Body": message,
	}

	if err := writeFields(writer, smsTemplate); err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	resp, err := c.request(ctx, url, "POST", body)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status %v, got %v", http.StatusCreated, resp.StatusCode)
	}

	return nil
}

func (c *client) request(ctx context.Context, url, method string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %w", err)
	}

	req.SetBasicAuth(c.accountSID, c.authToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}

	return resp, nil
}

func writeFields(writer *multipart.Writer, fields map[string]string) error {
	var err error

	for k, v := range fields {
		err = writer.WriteField(k, v)
		if err != nil {
			return fmt.Errorf("failed to write %s to %s: %w", v, k, err)
		}
	}

	return nil
}
