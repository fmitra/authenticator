package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// UserRepository is an implementation of auth.UserRepository.
type UserRepository struct {
	client *Client
}

// ByIdentity retrieves a User by their phone, email, or unique ID.
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

	row := r.client.queryRowContext(ctx, r.client.userQ[q], value)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.AuthReq, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Create persists a new User to local storage.
func (r *UserRepository) Create(ctx context.Context, user *auth.User) error {
	userID, err := ulid.New(ulid.Now(), r.client.entropy)
	if err != nil {
		return errors.Wrap(err, "cannot generate unique user ID")
	}

	// TODO Password, phone number and email validation
	// Bcrypt password
	user.ID = userID.String()
	row := r.client.queryRowContext(
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

// Update updates a User in storage.
func (r *UserRepository) Update(ctx context.Context, user *auth.User) error {
	currentTime := time.Now().UTC()
	user.UpdatedAt = currentTime

	res, err := r.client.execContext(
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

// GetForUpdate retrieves a User to be updated.
func (r *UserRepository) GetForUpdate(ctx context.Context, userID string) (*auth.User, error) {
	user := auth.User{}
	row := r.client.queryRowContext(ctx, r.client.userQ["forUpdate"], userID)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.AuthReq, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
