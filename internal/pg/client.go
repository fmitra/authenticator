package pg

import (
	"context"
	"database/sql"
	"math/rand"

	"github.com/go-kit/kit/log"
	// pg driver registers itself as being available to the database/sql package.
	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// Client represents a client for PostgreSQL
type Client struct {
	db     *sql.DB
	tx     *sql.Tx
	rand   *rand.Rand
	logger log.Logger

	LoginHistoryRepository *LoginHistoryRepository
	loginHistoryQ          map[string]string

	DeviceRepository *DeviceRepository
	deviceQ          map[string]string

	UserRepository *UserRepository
	userQ          map[string]string
}

// Open connects to PostgreSQL.
func (c *Client) Open(dataSourceName string) error {
	var err error

	c.logger.Log("level", "debug", "msg", "connecting to db")
	if c.db, err = sql.Open("postgres", dataSourceName); err != nil {
		return err
	}
	if err = c.db.Ping(); err != nil {
		return err
	}
	c.logger.Log("level", "debug", "msg", "connected to db")

	c.loginHistoryQ = map[string]string{
		"byUserID": `
			SELECT user_id, token_id, is_revoked, expires_at, created_at, updated_at
			FROM login_history
			WHERE user_id = $1
			LIMIT $2
			OFFSET $3;
		`,
		"forUpdate": `
			SELECT user_id, token_id, is_revoked, expires_at, created_at, updated_at
			FROM login_history
			WHERE token_id = $1;
		`,
		"update": `
			UPDATE login_history
			SET is_revoked=$2, updated_at=$3
			WHERE token_id = $1;
		`,
		"insert": `
			INSERT INTO login_history (
				user_id, token_id, is_revoked, expires_at
			)
			VALUES ($1, $2, $3, $4)
			RETURNING created_at, updated_at;
		`,
	}

	c.deviceQ = map[string]string{
		"forUpdate": `
			SELECT id, user_id, client_id, public_key, name, created_at, updated_at
			FROM device
			WHERE id = $1
			FOR UPDATE;
		`,
		"byClientID": `
			SELECT id, user_id, client_id, public_key, name, created_at, updated_at
			FROM device
			WHERE user_id = $1
			AND client_id = $2;
		`,
		"byUserID": `
			SELECT id, user_id, client_id, public_key, name, created_at, updated_at
			FROM device
			WHERE user_id = $1;
		`,
		"byID": `
			SELECT id, user_id, client_id, public_key, name, created_at, updated_at
			FROM device
			WHERE id = $1;
		`,
		"update": `
			UPDATE device
			SET client_id=$2, public_key=$3, name=$4, updated_at=$5
			WHERE id = $1;
		`,
		"insert": `
			INSERT INTO device (
				id, user_id, client_id, public_key, name
			)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING created_at, updated_at;
		`,
	}

	c.userQ = map[string]string{
		"forUpdate": `
			SELECT id, phone, email, password, tfa_secret, auth_req, is_verified,
				created_at, updated_at
			FROM auth_user
			WHERE id = $1
			FOR UPDATE;
		`,
		"byPhone": `
			SELECT id, phone, email, password, tfa_secret, auth_req, is_verified,
				created_at, updated_at
			FROM auth_user
			WHERE phone = $1;
		`,
		"byEmail": `
			SELECT id, phone, email, password, tfa_secret, auth_req, is_verified,
				created_at, updated_at
			FROM auth_user
			WHERE email = $1;
		`,
		"byID": `
			SELECT id, phone, email, password, tfa_secret, auth_req, is_verified,
				created_at, updated_at
			FROM auth_user
			WHERE id = $1;
		`,
		"update": `
			UPDATE auth_user
			SET phone=$2, email=$3, password=$4, tfa_secret=$5,
				auth_req=$6, is_verified=$7
			WHERE id=$1;
		`,
		"insert": `
			INSERT INTO auth_user (
				id, phone, email, password, tfa_secret, auth_req, is_verified
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING created_at, updated_at
		`,
	}

	return nil
}

// Close closes PostgreSQL connection.
func (c *Client) Close() error {
	return c.db.Close()
}

// WithTransaction starts a transaction and returns a client
// with the transaction set.
func (c *Client) NewWithTransaction(ctx context.Context) (auth.RepositoryManager, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}

	newClient := *c
	newClient.tx = tx
	newClient.LoginHistoryRepository.client = &newClient
	newClient.UserRepository.client = &newClient
	newClient.DeviceRepository.client = &newClient
	return &newClient, nil
}

// WithAtomic performs an operation within a transaction. If the operation
// is successful it commits it, otherwise the operation will be rolledback.
func (c *Client) WithAtomic(operation func() (interface{}, error)) (interface{}, error) {
	if c.tx == nil {
		return nil, errors.New("cannot complete operation outside of transaction")
	}

	entity, err := operation()

	defer func() {
		c.tx = nil
	}()

	if err == nil {
		return entity, errors.Wrap(c.tx.Commit(), "commit failed")
	}

	if dbErr := c.tx.Rollback(); dbErr != nil {
		err = errors.Wrap(err, dbErr.Error())
	}

	return nil, err
}

func (c *Client) Device() auth.DeviceRepository {
	return c.DeviceRepository
}

func (c *Client) LoginHistory() auth.LoginHistoryRepository {
	return c.LoginHistoryRepository
}

func (c *Client) User() auth.UserRepository {
	return c.UserRepository
}
