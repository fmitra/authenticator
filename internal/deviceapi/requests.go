package deviceapi

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type removeRequest struct {
	DeviceID string `json:"deviceID"`
}

func decodeRemoveRequest(r *http.Request) (*removeRequest, error) {
	var (
		req removeRequest
		err error
	)

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.DeviceID == "" {
		return nil, auth.ErrInvalidField("missing deviceID")
	}

	return &req, nil
}
