package pg

import (
	"context"
	"fmt"
	"time"

	auth "github.com/fmitra/authenticator"
)

type LoginHistoryRepository struct {
	client *Client
}

func (r *LoginHistoryRepository) ByUserID(ctx context.Context, userID string, limit, offset int) ([]*auth.LoginHistory, error) {
	rows, err := r.client.db.QueryContext(
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

func (r *LoginHistoryRepository) Create(ctx context.Context, login *auth.LoginHistory) error {
	row := r.client.db.QueryRowContext(
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

func (r *LoginHistoryRepository) Update(ctx context.Context, login *auth.LoginHistory) error {
	if r.client.tx == nil {
		return fmt.Errorf("cannot update login history outside of transaction")
	}

	currentTime := time.Now().UTC()
	login.UpdatedAt = currentTime

	res, err := r.client.tx.ExecContext(
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
		return fmt.Errorf("wrong number of devices updated: %d", updatedRows)
	}
	return nil
}

func (r *LoginHistoryRepository) GetForUpdate(ctx context.Context, tokenID string) (*auth.LoginHistory, error) {
	if r.client.tx == nil {
		return nil, fmt.Errorf("cannot retrieve user outside of transaction")
	}

	login := auth.LoginHistory{}
	row := r.client.tx.QueryRowContext(ctx, r.client.loginHistoryQ["forUpdate"], tokenID)
	err := row.Scan(
		&login.UserID, &login.TokenID, &login.IsRevoked, &login.ExpiresAt,
		&login.CreatedAt, &login.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &login, nil
}
