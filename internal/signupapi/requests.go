package signupapi

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type signupRequest struct {
	Identity string `json:"identity"`
	Type     string `json:"type"`
}

type signupVerifyRequest struct {
	Code string `json:"code"`
}

func (r *signupRequest) UserAttribute() string {
	switch r.Type {
	case "email":
		return "Email"
	case "phone":
		return "Phone"
	default:
		return ""
	}
}

func decodeSignupRequest(r *http.Request) (*signupRequest, error) {
	var (
		req signupRequest
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

func decodeSignupVerifyRequest(r *http.Request) (*signupVerifyRequest, error) {
	var (
		req signupVerifyRequest
		err error
	)

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	return &req, nil
}
