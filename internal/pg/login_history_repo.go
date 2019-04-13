package pg

import (
	"context"
	"time"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// LoginHistoryRepository is an implementation of auth.LoginHistoryRepository.
type LoginHistoryRepository struct {
	client *Client
}

// ByUserID retrieves all LoginHistory records associated with a User.
func (r *LoginHistoryRepository) ByUserID(ctx context.Context, userID string, limit, offset int) ([]*auth.LoginHistory, error) {
	rows, err := r.client.queryContext(
		ctx,
		r.client.loginHistoryQ["byUserID"],
		userID,
		limit,
		offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logins := make([]*auth.LoginHistory, 0)
	for rows.Next() {
		login := auth.LoginHistory{}
		err := rows.Scan(
			&login.UserID, &login.TokenID, &login.IsRevoked, &login.ExpiresAt,
			&login.CreatedAt, &login.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		logins = append(logins, &login)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logins, nil
}

// Create persists a new LoginHistory to storage.
func (r *LoginHistoryRepository) Create(ctx context.Context, login *auth.LoginHistory) error {
	row := r.client.queryRowContext(
		ctx,
		r.client.loginHistoryQ["insert"],
		login.UserID,
		login.TokenID,
		login.IsRevoked,
		login.ExpiresAt,
	)
	return row.Scan(
		&login.CreatedAt,
		&login.UpdatedAt,
	)
}

// Update updates a LoginHistory in storage.
func (r *LoginHistoryRepository) Update(ctx context.Context, login *auth.LoginHistory) error {
	currentTime := time.Now().UTC()
	login.UpdatedAt = currentTime

	res, err := r.client.execContext(
		ctx,
		r.client.loginHistoryQ["update"],
		login.TokenID,
		login.IsRevoked,
		login.UpdatedAt,
	)
	if err != nil {
		return err
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updatedRows != 1 {
		return errors.Errorf("wrong number of devices updated: %d", updatedRows)
	}
	return nil
}

// GetForUpdate retrieves a LoginHistory to be updated.
func (r *LoginHistoryRepository) GetForUpdate(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	login := auth.LoginHistory{}
	row := r.client.queryRowContext(ctx, r.client.loginHistoryQ["forUpdate"], tokenID)
	err := row.Scan(
		&login.UserID, &login.TokenID, &login.IsRevoked, &login.ExpiresAt,
		&login.CreatedAt, &login.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &login, nil
}
