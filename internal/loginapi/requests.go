package loginapi

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

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
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.UserAttribute() == "" {
		return nil, auth.ErrBadRequest("identity type must be email or phone")
	}

	return &req, nil
}

func decodeVerifyCodeRequest(r *http.Request) (*verifyCodeRequest, error) {
	var (
		req verifyCodeRequest
		err error
	)

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	return &req, nil
}
