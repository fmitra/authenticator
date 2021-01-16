package postgres

import (
	"context"
	"fmt"
	"time"

	auth "github.com/fmitra/authenticator"
)

// LoginHistoryRepository is an implementation of auth.LoginHistoryRepository.
type LoginHistoryRepository struct {
	client *Client
}

// ByTokenID retrieves a LoginHistory record with matching JWT token ID.
func (r *LoginHistoryRepository) ByTokenID(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	login := auth.LoginHistory{}
	row := r.client.queryRowContext(ctx, r.client.loginHistoryQ["byTokenID"], tokenID)
	err := row.Scan(
		&login.UserID, &login.TokenID, &login.IPAddress, &login.IsRevoked, &login.ExpiresAt,
		&login.CreatedAt, &login.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &login, nil
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
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	logins := make([]*auth.LoginHistory, 0)
	for rows.Next() {
		login := auth.LoginHistory{}
		err := rows.Scan(
			&login.UserID, &login.TokenID, &login.IPAddress, &login.IsRevoked, &login.ExpiresAt,
			&login.CreatedAt, &login.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		logins = append(logins, &login)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("completed with error: %w", err)
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
		login.IPAddress,
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
		login.IPAddress,
		login.IsRevoked,
		login.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to execute update: %w", err)
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if updatedRows != 1 {
		return fmt.Errorf("wrong number of devices updated: %d", updatedRows)
	}
	return nil
}

// GetForUpdate retrieves a LoginHistory to be updated.
func (r *LoginHistoryRepository) GetForUpdate(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	login := auth.LoginHistory{}
	row := r.client.queryRowContext(ctx, r.client.loginHistoryQ["forUpdate"], tokenID)
	err := row.Scan(
		&login.UserID, &login.TokenID, &login.IPAddress, &login.IsRevoked, &login.ExpiresAt,
		&login.CreatedAt, &login.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve record for update: %w", err)
	}

	return &login, nil
}
