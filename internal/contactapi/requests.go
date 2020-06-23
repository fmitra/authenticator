package contactapi

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/contactchecker"
)

type verifyRequest struct {
	Code string `json:"code"`
	// IsDisabled represents a user's optional request to not
	// enable a verified address a 2FA delivery option
	// for OTP codes.
	IsDisabled   bool `json:"is_disabled"`
	IsOTPEnabled bool
}

type deactivateRequest struct {
	DeliveryMethod auth.DeliveryMethod `json:"delivery_method"`
}

type deliveryRequest struct {
	Address        string              `json:"address"`
	DeliveryMethod auth.DeliveryMethod `json:"delivery_method"`
}

func decodeDeliveryRequest(r *http.Request) (*deliveryRequest, error) {
	var (
		req deliveryRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.Address == "" {
		return nil, auth.ErrInvalidField("address cannot be empty")
	}

	if req.DeliveryMethod != auth.Phone && req.DeliveryMethod != auth.Email {
		return nil, auth.ErrInvalidField("delivery_method must be `phone` or `email`")
	}

	if !contactchecker.Validator(req.DeliveryMethod)(req.Address) {
		return nil, auth.ErrInvalidField("address format is invalid")
	}

	return &req, nil
}

func decodeDeactivateRequest(r *http.Request) (*deactivateRequest, error) {
	var (
		req deactivateRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.DeliveryMethod != auth.Phone && req.DeliveryMethod != auth.Email {
		return nil, auth.ErrInvalidField("delivery_method must be `phone` or `email`")
	}

	return &req, nil
}

func decodeVerifyRequest(r *http.Request) (*verifyRequest, error) {
	var (
		req verifyRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.Code == "" {
		return nil, auth.ErrInvalidField("code cannot be empty")
	}

	req.IsOTPEnabled = true
	if req.IsDisabled {
		req.IsOTPEnabled = false
	}

	return &req, nil
}
