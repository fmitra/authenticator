package signupapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/fmitra/authenticator"
)

type signupRequest struct {
	Password string              `json:"password"`
	Identity string              `json:"identity"`
	Type     auth.DeliveryMethod `json:"type"`
}

type signupVerifyRequest struct {
	Code string `json:"code"`
}

func (r *signupRequest) UserAttribute() string {
	switch r.Type {
	case auth.Email:
		return "Email"
	case auth.Phone:
		return "Phone"
	default:
		return ""
	}
}

func (r *signupRequest) ToUser() *auth.User {
	user := auth.User{
		Password: r.Password,
	}

	identity := sql.NullString{
		String: r.Identity,
		Valid:  true,
	}

	if r.Type == "email" {
		user.Email = identity
	}

	if r.Type == "phone" {
		user.Phone = identity
	}

	return &user
}

func decodeSignupRequest(r *http.Request) (*signupRequest, error) {
	var (
		req signupRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

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

func decodeSignupVerifyRequest(r *http.Request) (*signupVerifyRequest, error) {
	var (
		req signupVerifyRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	req.Code = strings.TrimSpace(req.Code)

	return &req, nil
}
