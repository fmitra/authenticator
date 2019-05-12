package test

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// PGClient provies a test database.
type PGClient struct {
	DB     *sql.DB
	dbName string
}

// NewPGDB returns a new database for testing. Database
// names are randomly generated to avoid race conditions with
// tear down and set up methods with tests.
func NewPGDB() (*PGClient, error) {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	testDBName := randomDB()

	sysDBName := "postgres"
	connectionString := "user=auth password=swordfish host=%s port=5432 dbname=%s connect_timeout=3 sslmode=disable"

	testConnDetails := fmt.Sprintf(connectionString, host, testDBName)
	sysConnDetails := fmt.Sprintf(connectionString, host, sysDBName)

	sysDB, err := sql.Open("postgres", sysConnDetails)
	if err != nil {
		return nil, errors.Wrap(err, "system db connect failed")
	}
	defer sysDB.Close()

	_, err = sysDB.Exec("DROP DATABASE IF EXISTS " + testDBName)
	if err != nil {
		return nil, errors.Wrap(err, "test DB drop failed")
	}

	_, err = sysDB.Exec("CREATE DATABASE " + testDBName)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create test DB")
	}

	db, err := sql.Open("postgres", testConnDetails)
	if err != nil {
		return nil, errors.Wrap(err, "cannot connect to test DB")
	}
	if err = db.Ping(); err != nil {
		return nil, errors.Wrap(err, "no response to ping")
	}

	_, err = db.Exec(auth.Schema)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tables")
	}

	return &PGClient{
		DB:     db,
		dbName: testDBName,
	}, nil
}

// randomDB creates a random test database name.
func randomDB() string {
	rand.Seed(time.Now().UnixNano())

	length := 10
	b := make([]rune, length)
	opts := []rune("abcdefghijklmnopqrstuvwxyz")
	for i := range b {
		b[i] = opts[rand.Intn(len(opts))]
	}

	return fmt.Sprintf("authenticator_test_%s", string(b))
}

// DropDB removes a recently created test database.
func (c *PGClient) DropDB() error {
	c.DB.Close()

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

	_, err = sysDB.Exec("DROP DATABASE IF EXISTS " + c.dbName)
	return err
}
