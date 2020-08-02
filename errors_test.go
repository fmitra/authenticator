package authenticator

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestErrors_RetrieveDomainErrorCode(t *testing.T) {
	tt := []struct {
		name string
		code ErrCode
		err  error
	}{
		{
			name: "Typed error",
			code: EInvalidCode,
			err:  ErrInvalidCode("invalid code"),
		},
		{
			name: "stdlib error",
			code: EInternal,
			err:  fmt.Errorf("whoops"),
		},
		{
			name: "Wrapped error",
			code: EBadRequest,
			err:  fmt.Errorf("whoops: %w", ErrBadRequest("bad request")),
		},
		{
			name: "Multi layered error",
			code: EInvalidToken,
			err: fmt.Errorf("whoops: %w",
				fmt.Errorf("wrapped: %w", ErrInvalidToken("bad token")),
			),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			code := ErrorCode(tc.err)
			if code != tc.code {
				t.Error("code does not match", cmp.Diff(code, tc.code))
			}
		})
	}
}
