package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/go-kit/kit/log"
	// pg driver registers itself as being available to the database/sql package.
	_ "github.com/lib/pq"

	auth "github.com/fmitra/authenticator"
)

// Client represents a client for PostgreSQL.
type Client struct {
	db      *sql.DB
	tx      *sql.Tx
	entropy io.Reader
	logger  log.Logger

	loginHistoryRepository *LoginHistoryRepository
	loginHistoryQ          map[string]string

	deviceRepository *DeviceRepository
	deviceQ          map[string]string

	userRepository *UserRepository
	userQ          map[string]string
}

func (c *Client) createQueries() {
	c.loginHistoryQ = map[string]string{
		"byTokenID": `
			SELECT user_id, token_id, is_revoked, expires_at, created_at, updated_at
			FROM login_history
			WHERE token_id = $1;
		`,
		"byUserID": `
			SELECT user_id, token_id, is_revoked, expires_at, created_at, updated_at
			FROM login_history
			WHERE user_id = $1
			ORDER BY created_at
			DESC
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
			SELECT id, user_id, client_id, public_key, name, aaguid, sign_count,
				created_at, updated_at
			FROM device
			WHERE id = $1
			FOR UPDATE;
		`,
		"byUserID": `
			SELECT id, user_id, client_id, public_key, name, aaguid, sign_count,
				created_at, updated_at
			FROM device
			WHERE user_id = $1;
		`,
		"byClientID": `
			SELECT id, user_id, client_id, public_key, name, aaguid, sign_count,
				created_at, updated_at
			FROM device
			WHERE user_id = $1
			AND client_id = $2;
		`,
		"byID": `
			SELECT id, user_id, client_id, public_key, name, aaguid, sign_count,
				created_at, updated_at
			FROM device
			WHERE id = $1;
		`,
		"update": `
			UPDATE device
			SET client_id=$2, public_key=$3, name=$4, sign_count=$5, updated_at=$6
			WHERE id = $1;
		`,
		"insert": `
			INSERT INTO device (
				id, user_id, client_id, public_key, name, aaguid, sign_count
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING created_at, updated_at;
		`,
		"delete": `
			DELETE FROM device WHERE id=$1 AND user_id=$2;
		`,
	}

	c.userQ = map[string]string{
		"forUpdate": `
			SELECT id, phone, email, password, tfa_secret, is_email_otp_allowed, is_sms_otp_allowed,
				is_totp_allowed, is_device_allowed, is_verified, created_at, updated_at
			FROM auth_user
			WHERE id = $1
			FOR UPDATE;
		`,
		"byPhone": `
			SELECT id, phone, email, password, tfa_secret, is_email_otp_allowed, is_sms_otp_allowed,
				is_totp_allowed, is_device_allowed, is_verified, created_at, updated_at
			FROM auth_user
			WHERE phone = $1;
		`,
		"byEmail": `
			SELECT id, phone, email, password, tfa_secret, is_email_otp_allowed, is_sms_otp_allowed,
				is_totp_allowed, is_device_allowed, is_verified, created_at, updated_at
			FROM auth_user
			WHERE email = $1;
		`,
		"byID": `
			SELECT id, phone, email, password, tfa_secret, is_email_otp_allowed, is_sms_otp_allowed,
				is_totp_allowed, is_device_allowed, is_verified, created_at, updated_at
			FROM auth_user
			WHERE id = $1;
		`,
		"update": `
			UPDATE auth_user
			SET phone=$2, email=$3, password=$4, tfa_secret=$5,
				is_email_otp_allowed=$6, is_sms_otp_allowed=$7, is_totp_allowed=$8, is_device_allowed=$9,
				is_verified=$10, created_at=$11, updated_at=$12, id=$13
			WHERE id=$1;
		`,
		"insert": `
			INSERT INTO auth_user (
				id, phone, email, password, tfa_secret, is_email_otp_allowed, is_sms_otp_allowed,
					is_totp_allowed, is_device_allowed, is_verified
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING created_at, updated_at
		`,
	}
}

// NewWithTransaction returns a new client with a transaction. All
// repository operations using the new client will default to the transaction.
func (c *Client) NewWithTransaction(ctx context.Context) (auth.RepositoryManager, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}

	newClient := *c
	newClient.tx = tx
	newClient.loginHistoryRepository.client = &newClient
	newClient.userRepository.client = &newClient
	newClient.deviceRepository.client = &newClient
	return &newClient, nil
}

// WithAtomic performs an operation within a transaction. If the operation
// is successful it commits it, otherwise the operation will be rolledback.
func (c *Client) WithAtomic(operation func() (interface{}, error)) (interface{}, error) {
	if c.tx == nil {
		return nil, fmt.Errorf("cannot complete operation outside of transaction")
	}

	defer func() {
		c.tx = nil
	}()

	entity, err := operation()

	if err != nil {
		if dbErr := c.tx.Rollback(); dbErr != nil {
			err = fmt.Errorf("%v: %w", dbErr, err)
		}
		return nil, err
	}

	err = c.tx.Commit()
	if err != nil {
		return entity, fmt.Errorf("commit failed: %w", err)
	}

	return entity, nil
}

// Device returns a DeviceRepository.
func (c *Client) Device() auth.DeviceRepository {
	return c.deviceRepository
}

// LoginHistory returns a LoginRepository.
func (c *Client) LoginHistory() auth.LoginHistoryRepository {
	return c.loginHistoryRepository
}

// User returns a UserRepository.
func (c *Client) User() auth.UserRepository {
	return c.userRepository
}

func (c *Client) queryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	if c.tx != nil {
		return c.tx.QueryRowContext(ctx, query, args...)
	}

	return c.db.QueryRowContext(ctx, query, args...)
}

func (c *Client) queryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if c.tx != nil {
		return c.tx.QueryContext(ctx, query, args...)
	}

	return c.db.QueryContext(ctx, query, args...)
}

func (c *Client) execContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if c.tx != nil {
		return c.tx.ExecContext(ctx, query, args...)
	}

	return c.db.ExecContext(ctx, query, args...)
}
