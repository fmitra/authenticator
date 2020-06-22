package contactapi

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type checkAddressRequest struct {
	Address string `json:"address"`
	DeliveryMethod auth.DeliveryMethod `json:"delivery_method"`
}

func decodeCheckAddressRequest(r *http.Request) (*checkAddressRequest, error) {
	var (
		req checkAddressRequest
		err error
	)

	if r == nil || r.Body == nil {
		return nil, auth.ErrBadRequest("no request body received")
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid JSON request"), err.Error())
	}

	if req.Address == "" {
		return nil, auth.ErrBadRequest("address cannot be empty")
	}

	if string(req.DeliveryMethod) == "" {
		return nil, auth.ErrBadRequest("delivery_method must be `phone` or `email`")
	}

	return &req, nil
}
