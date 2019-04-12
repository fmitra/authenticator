package pg

import (
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/oklog/ulid"
)

// NewTestClient returns a new Client connected to a test database.
// We allow specifying a test DB name to avoid race conditions
// in environment cleanup while tests run in parallel.
func NewTestClient(testDBName string) (*Client, error) {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	if testDBName == "" {
		testDBName = "authenticator_test"
	}

	sysDBName := "postgres"
	connectionString := "user=auth password=swordfish host=%s port=5432 dbname=%s connect_timeout=3 sslmode=disable"

	testConnDetails := fmt.Sprintf(connectionString, host, testDBName)
	sysConnDetails := fmt.Sprintf(connectionString, host, sysDBName)

	sysDB, err := sql.Open("postgres", sysConnDetails)
	if err != nil {
		return nil, err
	}
	defer sysDB.Close()

	_, err = sysDB.Exec("DROP DATABASE IF EXISTS " + testDBName)
	if err != nil {
		return nil, err
	}

	_, err = sysDB.Exec("CREATE DATABASE " + testDBName)
	if err != nil {
		return nil, err
	}

	var entropy io.Reader
	{
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		entropy = ulid.Monotonic(random, 0)
	}

	testClient := NewClient(
		WithLogger(log.NewNopLogger()),
		WithEntropy(entropy),
	)
	err = testClient.Open(testConnDetails)
	if err != nil {
		return nil, err
	}

	_, err = testClient.db.Exec(Schema)
	if err != nil {
		return nil, err
	}

	return testClient, nil
}

// DropTestDB removes a newly created test DB
func DropTestDB(c *Client, testDBName string) error {
	c.Close()

	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	sysDBName := "postgres"
	connectionString := "user=auth password=swordfish host=%s port=5432 dbname=%s connect_timeout=3 sslmode=disable"

	sysConnDetails := fmt.Sprintf(connectionString, host, sysDBName)

	sysDB, err := sql.Open("postgres", sysConnDetails)
	if err != nil {
		return err
	}
	defer sysDB.Close()

	_, err = sysDB.Exec("DROP DATABASE IF EXISTS " + testDBName)
	return err
}
