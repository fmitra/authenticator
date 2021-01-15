package loginhistoryapi

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	auth "github.com/fmitra/authenticator"
)

func TestLoginHistoryAPI_ListRequest(t *testing.T) {
	tt := []struct {
		name   string
		url    string
		err    error
		offset int
		limit  int
	}{
		{
			name:   "Parses request with custom limit/offset",
			url:    "https://api.authenticator.com/v1/login-history-api?limit=20&offset=20",
			err:    nil,
			offset: 20,
			limit:  20,
		},
		{
			name:   "Sets default limit/offset",
			url:    "https://api.authenticator.com/v1/login-history-api",
			err:    nil,
			offset: 0,
			limit:  10,
		},
		{
			name:   "Fails to parse request",
			url:    "https://api.authenticator.com/v1/login-history-api?limit=foo&offset=bar",
			err:    auth.ErrBadRequest("pagination param should be a number"),
			offset: 0,
			limit:  0,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", tc.url, nil)
			if err != nil {
				t.Fatal("failed to create mock request:", err)
			}

			opt := cmpopts.EquateErrors()
			pr, err := decodePaginatedRequest(r)
			if !cmp.Equal(err, tc.err, opt) {
				t.Error("error value does not match", cmp.Diff(err, tc.err))
			}

			if tc.limit != 0 && pr.Limit != tc.limit {
				t.Error("limit does not match", cmp.Diff(pr.Limit, tc.limit))
			}

			if tc.offset != 0 && pr.Offset != tc.offset {
				t.Error("offset does not match", cmp.Diff(pr.Offset, tc.offset))
			}
		})
	}
}
