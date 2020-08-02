package contactchecker

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	auth "github.com/fmitra/authenticator"
)

func TestContactChecker_ValidatesPhone(t *testing.T) {
	tt := []struct {
		name string
		in   string
		out  bool
	}{
		{
			name: "Valid phone number",
			in:   "+6594867353",
			out:  true,
		},
		{
			name: "Invalid phone number without country code",
			in:   "94867353",
			out:  false,
		},
		{
			name: "Invalid phone number without prefix",
			in:   "6594867353",
			out:  false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res := Validator(auth.Phone)(tc.in)
			if res != tc.out {
				t.Error("phone validation failed", cmp.Diff(res, tc.out))
			}
		})
	}
}

func TestContactChecker_ValidatesEmail(t *testing.T) {
	tt := []struct {
		name string
		in   string
		out  bool
	}{
		{
			name: "Valid email address",
			in:   "jane@example.com",
			out:  true,
		},
		{
			name: "Invalid email address with no second level domain",
			in:   "jane@",
			out:  false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res := Validator(auth.Email)(tc.in)
			if res != tc.out {
				t.Error("email validation failed", cmp.Diff(res, tc.out))
			}
		})
	}
}
