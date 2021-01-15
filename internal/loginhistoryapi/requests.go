package loginhistoryapi

import (
	"net/http"
	"strconv"

	auth "github.com/fmitra/authenticator"
)

type paginatedRequest struct {
	Limit  int
	Offset int
}

func decodePaginatedRequest(r *http.Request) (*paginatedRequest, error) {
	var pr paginatedRequest

	if r == nil {
		return nil, auth.ErrBadRequest("invalid request")
	}

	params := r.URL.Query()

	const defaultLimit = 10
	const defaultOffset = 0

	limit, err := toIntOrDefault(params.Get("limit"), defaultLimit)
	if err != nil {
		return nil, err
	}

	offset, err := toIntOrDefault(params.Get("offset"), defaultOffset)
	if err != nil {
		return nil, err
	}

	pr.Limit = limit
	pr.Offset = offset

	return &pr, nil
}

func toIntOrDefault(s string, i int) (int, error) {
	if s == "" {
		return i, nil
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, auth.ErrBadRequest("pagination param should be a number")
	}

	return n, nil
}
