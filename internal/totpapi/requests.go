package totpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/fmitra/authenticator"
)

type totpRequest struct {
	Code string `json:"code"`
}

func decodeTOTPRequest(r *http.Request) (*totpRequest, error) {
	var req totpRequest

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	if req.Code == "" {
		return nil, auth.ErrBadRequest("code must be provided")
	}

	req.Code = strings.TrimSpace(req.Code)

	return &req, nil
}
