package totpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type totpRequest struct {
	Code string `json:"code"`
}

func decodeTOTPRequest(r *http.Request) (*totpRequest, error) {
	var (
		req totpRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.Code == "" {
		return nil, auth.ErrBadRequest("code must be provided")
	}

	req.Code = strings.TrimSpace(req.Code)

	return &req, nil
}
