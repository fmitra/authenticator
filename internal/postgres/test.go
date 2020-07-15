package postgres

import (
	"database/sql"

	"github.com/go-kit/kit/log"

	"github.com/fmitra/authenticator/internal/password"
)

// TestClient returns a test client with necessary dependencies
// already provided.
func TestClient(db *sql.DB) *Client {
	passwordSvc := password.NewPassword()
	testClient := NewClient(
		WithLogger(log.NewNopLogger()),
		WithPassword(passwordSvc),
		WithDB(db),
	)

	return testClient
}
