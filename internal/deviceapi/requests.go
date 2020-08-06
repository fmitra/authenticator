package deviceapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth "github.com/fmitra/authenticator"
)

type renameRequest struct {
	Name string `json:"name"`
}

func decodeRenameRequest(r *http.Request) (*renameRequest, error) {
	var (
		req renameRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("invalid JSON request"))
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return nil, auth.ErrBadRequest("name cannot be blank")
	}

	return &req, nil
}
