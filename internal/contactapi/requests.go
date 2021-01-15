package contactapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/contactchecker"
)

type verifyRequest struct {
	Code string `json:"code"`
	// IsDisabled represents a user's optional request to not
	// enable a verified address a 2FA delivery option
	// for OTP codes.
	IsDisabled   bool `json:"isDisabled"`
	IsOTPEnabled bool
}

type deactivateRequest struct {
	DeliveryMethod auth.DeliveryMethod `json:"deliveryMethod"`
}

type deliveryRequest struct {
	Address        string              `json:"address"`
	DeliveryMethod auth.DeliveryMethod `json:"deliveryMethod"`
}

type sendRequest struct {
	DeliveryMethod auth.DeliveryMethod `json:"deliveryMethod"`
}

func decodeSendRequest(r *http.Request) (*sendRequest, error) {
	var req sendRequest

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.DeliveryMethod != auth.Phone && req.DeliveryMethod != auth.Email {
		return nil, auth.ErrInvalidField("deliveryMethod must be `phone` or `email`")
	}

	return &req, nil
}

func decodeDeliveryRequest(r *http.Request) (*deliveryRequest, error) {
	var req deliveryRequest

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.Address == "" {
		return nil, auth.ErrInvalidField("address cannot be empty")
	}

	if req.DeliveryMethod != auth.Phone && req.DeliveryMethod != auth.Email {
		return nil, auth.ErrInvalidField("deliveryMethod must be `phone` or `email`")
	}

	if !contactchecker.Validator(req.DeliveryMethod)(req.Address) {
		return nil, auth.ErrInvalidField("address format is invalid")
	}

	req.Address = strings.ToLower(strings.TrimSpace(req.Address))

	return &req, nil
}

func decodeDeactivateRequest(r *http.Request) (*deactivateRequest, error) {
	var req deactivateRequest

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.DeliveryMethod != auth.Phone && req.DeliveryMethod != auth.Email {
		return nil, auth.ErrInvalidField("deliveryMethod must be `phone` or `email`")
	}

	return &req, nil
}

func decodeVerifyRequest(r *http.Request) (*verifyRequest, error) {
	var req verifyRequest

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.Code == "" {
		return nil, auth.ErrInvalidField("code cannot be empty")
	}

	req.IsOTPEnabled = true
	if req.IsDisabled {
		req.IsOTPEnabled = false
	}

	req.Code = strings.TrimSpace(req.Code)

	return &req, nil
}
