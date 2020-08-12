// Package twilio exposes Twilio's REST API.
package twilio

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

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

	resp, err := c.request(ctx, url, body, writer)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		rBody, _ := ioutil.ReadAll(resp.Body)

		return fmt.Errorf("expected status %v, got %v: %s",
			http.StatusCreated, resp.StatusCode, string(rBody))
	}

	return nil
}

func (c *client) request(ctx context.Context, url string, body io.Reader, writer *multipart.Writer) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %w", err)
	}

	req.SetBasicAuth(c.accountSID, c.authToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

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
