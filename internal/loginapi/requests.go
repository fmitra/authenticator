package loginapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/fmitra/authenticator"
)

type loginRequest struct {
	Password string              `json:"password"`
	Identity string              `json:"identity"`
	Type     auth.DeliveryMethod `json:"type"`
}

type verifyCodeRequest struct {
	Code string `json:"code"`
}

func (r *loginRequest) UserAttribute() string {
	switch r.Type {
	case auth.Email:
		return "Email"
	case auth.Phone:
		return "Phone"
	default:
		return ""
	}
}

func decodeLoginRequest(r *http.Request) (*loginRequest, error) {
	var (
		req loginRequest
		err error
	)

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.UserAttribute() == "" {
		return nil, auth.ErrBadRequest("identity type must be email or phone")
	}

	req.Identity = strings.TrimSpace(req.Identity)

	return &req, nil
}

func decodeVerifyCodeRequest(r *http.Request) (*verifyCodeRequest, error) {
	var (
		req verifyCodeRequest
		err error
	)

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	req.Code = strings.TrimSpace(req.Code)

	return &req, nil
}
