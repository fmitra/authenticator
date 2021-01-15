package loginhistoryapi

import (
	auth "github.com/fmitra/authenticator"
)

// listResponse is a success response for LoginHistoryAPI.List.
type listResponse struct {
	LoginHistory []*auth.LoginHistory `json:"loginHistory"`
}

// Create populates a response list with a list of LoginHistory records.
func (r *listResponse) Create(records []*auth.LoginHistory) {
	r.LoginHistory = records
}
