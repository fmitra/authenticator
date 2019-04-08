package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type UserRepository struct {
	client *Client
}

func (r *UserRepository) ByIdentity(ctx context.Context, attribute, value string) (*auth.User, error) {
	var (
		q    string
		user auth.User
	)

	switch attribute {
	case "Phone":
		q = "byPhone"
	case "Email":
		q = "byEmail"
	case "ID":
		q = "byID"
	default:
		return nil, fmt.Errorf("%s is not a valid query paramter", attribute)
	}

	row := r.client.db.QueryRowContext(ctx, r.client.userQ[q], value)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.AuthReq, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user *auth.User) error {
	entropy := ulid.Monotonic(r.client.rand, 0)
	userID, err := ulid.New(ulid.Now(), entropy)
	if err != nil {
		return errors.Wrap(err, "cannot generate unique user ID")
	}

	// TODO Phone number and email validation
	user.ID = userID.String()
	row := r.client.db.QueryRowContext(
		ctx,
		r.client.userQ["insert"],
		user.ID,
		user.Phone,
		user.Email,
		user.Password,
		user.TFASecret,
		user.AuthReq,
		user.IsVerified,
	)
	err = row.Scan(
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	return err
}

func (r *UserRepository) Update(ctx context.Context, user *auth.User) error {
	if r.client.tx == nil {
		return fmt.Errorf("cannot update user outside of transaction")
	}

	currentTime := time.Now().UTC()
	user.UpdatedAt = currentTime

	res, err := r.client.tx.ExecContext(
		ctx,
		r.client.userQ["update"],
		user.ID,
		user.Phone,
		user.Email,
		user.Password,
		user.TFASecret,
		user.AuthReq,
		user.IsVerified,
	)
	if err != nil {
		return err
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updatedRows != 1 {
		return fmt.Errorf("wrong number of users updated: %d", updatedRows)
	}
	return nil
}

func (r *UserRepository) GetForUpdate(ctx context.Context, userID string) (*auth.User, error) {
	if r.client.tx == nil {
		return nil, fmt.Errorf("cannot retrieve user outside of transaction")
	}

	user := auth.User{}
	row := r.client.tx.QueryRowContext(ctx, r.client.userQ["forUpdate"], userID)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.AuthReq, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
