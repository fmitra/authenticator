package postgres

import (
	"database/sql"
	"io"
	"math/rand"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/oklog/ulid"

	"github.com/fmitra/authenticator/internal/password"
)

// TestClient returns a test client with necessary dependencies
// already provided.
func TestClient(db *sql.DB) *Client {
	var entropy io.Reader
	{
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		entropy = ulid.Monotonic(random, 0)
	}

	passwordSvc := password.NewPassword()
	testClient := NewClient(
		WithLogger(log.NewNopLogger()),
		WithEntropy(entropy),
		WithPassword(passwordSvc),
		WithDB(db),
	)

	return testClient
}
