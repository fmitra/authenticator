package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/contactchecker"
)

// UserRepository is an implementation of auth.UserRepository.
type UserRepository struct {
	client   *Client
	password auth.PasswordService
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
		return nil, fmt.Errorf("%s is not a valid query parameter", attribute)
	}

	row := r.client.queryRowContext(ctx, r.client.userQ[q], value)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.IsEmailOTPAllowed, &user.IsPhoneOTPAllowed, &user.IsTOTPAllowed, &user.IsDeviceAllowed,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Create persists a new User to local storage.
func (r *UserRepository) Create(ctx context.Context, user *auth.User) error {
	sanitizeUser(user)
	err := validateUserFields(
		user,
		validateIdentity,
		validateEmail,
		validatePhone,
	)
	if err != nil {
		return err
	}

	userID, err := ulid.New(ulid.Now(), r.client.entropy)
	if err != nil {
		return fmt.Errorf("cannot generate unique user ID: %w", err)
	}

	if err = r.hashPassword(user); err != nil {
		return err
	}

	if user.Phone.String != "" {
		user.IsPhoneOTPAllowed = true
	}

	if user.Email.String != "" {
		user.IsEmailOTPAllowed = true
	}

	user.ID = userID.String()
	row := r.client.queryRowContext(
		ctx,
		r.client.userQ["insert"],
		user.ID,
		user.Phone,
		user.Email,
		user.Password,
		user.TFASecret,
		user.IsEmailOTPAllowed,
		user.IsPhoneOTPAllowed,
		user.IsTOTPAllowed,
		user.IsDeviceAllowed,
		user.IsVerified,
	)
	err = row.Scan(
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	return err
}

// ReCreate updates an existing unverified User record
// with new a new creation timestamp and primary key value
// to treat the user as a newly created record. New Users
// remain in an unverified state until completing OTP
// verification to prove ownership of a phone or email address.
func (r *UserRepository) ReCreate(ctx context.Context, user *auth.User) error {
	sanitizeUser(user)
	err := validateUserFields(
		user,
		validateIdentity,
		validateEmail,
		validatePhone,
		validateUserUnverified,
	)
	if err != nil {
		return err
	}

	userID, err := ulid.New(ulid.Now(), r.client.entropy)
	if err != nil {
		return fmt.Errorf("cannot generate unique user ID: %w", err)
	}

	if err = r.hashPassword(user); err != nil {
		return err
	}

	currentTime := time.Now().UTC()
	oldID := user.ID
	user.ID = userID.String()
	user.UpdatedAt = currentTime
	user.CreatedAt = currentTime

	return r.update(ctx, oldID, user)
}

// Update updates a User in storage.
func (r *UserRepository) Update(ctx context.Context, user *auth.User) error {
	return r.update(ctx, user.ID, user)
}

// GetForUpdate retrieves a User to be updated.
func (r *UserRepository) GetForUpdate(ctx context.Context, userID string) (*auth.User, error) {
	user := auth.User{}
	row := r.client.queryRowContext(ctx, r.client.userQ["forUpdate"], userID)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.IsEmailOTPAllowed, &user.IsPhoneOTPAllowed, &user.IsTOTPAllowed, &user.IsDeviceAllowed,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve record for update: %w", err)
	}

	return &user, nil
}

// RemoveDeliveryMethod removes a phone or email from a User.
func (r *UserRepository) RemoveDeliveryMethod(ctx context.Context, userID string, method auth.DeliveryMethod) (*auth.User, error) {
	txClient, err := r.client.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	entity, err := txClient.WithAtomic(func() (interface{}, error) {
		user, err := txClient.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		if method == auth.Phone {
			user.IsPhoneOTPAllowed = false
			user.Phone = sql.NullString{
				String: "",
				Valid:  false,
			}
		}

		if method == auth.Email {
			user.IsEmailOTPAllowed = false
			user.Email = sql.NullString{
				String: "",
				Valid:  false,
			}
		}

		isTFADisabled := !user.IsPhoneOTPAllowed && !user.IsEmailOTPAllowed &&
			!user.IsDeviceAllowed && !user.IsTOTPAllowed

		isContactDisabled := !user.Phone.Valid && !user.Email.Valid

		if isTFADisabled {
			return nil, auth.ErrInvalidField(
				fmt.Sprintf("a 2FA option must be enabled to remove %s", string(method)),
			)
		}

		if isContactDisabled {
			return nil, auth.ErrInvalidField(
				fmt.Sprintf("a contact address must be enabled to remove %s", string(method)),
			)
		}

		if err = txClient.User().Update(ctx, user); err != nil {
			return nil, err
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	user := entity.(*auth.User)
	return user, nil
}

// DisableOTP disables an OTP delivery method for a User.
func (r *UserRepository) DisableOTP(ctx context.Context, userID string, method auth.DeliveryMethod) (*auth.User, error) {
	txClient, err := r.client.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	entity, err := txClient.WithAtomic(func() (interface{}, error) {
		user, err := txClient.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		if method == auth.Phone {
			user.IsPhoneOTPAllowed = false
		}

		if method == auth.Email {
			user.IsEmailOTPAllowed = false
		}

		isTFADisabled := !user.IsPhoneOTPAllowed && !user.IsEmailOTPAllowed &&
			!user.IsDeviceAllowed && !user.IsTOTPAllowed

		if isTFADisabled {
			return nil, auth.ErrInvalidField(
				fmt.Sprintf("a 2FA option must be enabled to disable %s OTP", string(method)),
			)
		}

		if err = txClient.User().Update(ctx, user); err != nil {
			return nil, err
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	user := entity.(*auth.User)
	return user, nil
}

func (r *UserRepository) update(ctx context.Context, userID string, user *auth.User) error {
	currentTime := time.Now().UTC()
	user.UpdatedAt = currentTime

	res, err := r.client.execContext(
		ctx,
		r.client.userQ["update"],
		userID,
		user.Phone,
		user.Email,
		user.Password,
		user.TFASecret,
		user.IsEmailOTPAllowed,
		user.IsPhoneOTPAllowed,
		user.IsTOTPAllowed,
		user.IsDeviceAllowed,
		user.IsVerified,
		// We support updating CreatedAt and ID fields
		// in order to treat re-registrations
		// of unverified users as a new user.
		user.CreatedAt,
		user.UpdatedAt,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to execute update: %w", err)
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if updatedRows != 1 {
		return fmt.Errorf("wrong number of users updated: %d", updatedRows)
	}
	return nil
}

func (r *UserRepository) hashPassword(user *auth.User) error {
	err := r.password.OKForUser(user.Password)
	if err != nil {
		return err
	}

	passwordHash, err := r.password.Hash(user.Password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.Password = string(passwordHash)
	return nil
}

// validateUserFields proccesses an arbitrary number of user entity
// validator functions.
func validateUserFields(user *auth.User, validators ...func(user *auth.User) error) error {
	for _, validator := range validators {
		err := validator(user)
		if err != nil {
			return err
		}
	}
	return nil
}

// validateIdentity ensures a user's email and phone
// cannot be blank at the same time.
func validateIdentity(user *auth.User) error {
	if user.Email.String == "" && user.Phone.String == "" {
		return auth.ErrInvalidField("user must have either an email or phone")
	}
	return nil
}

// validateEmail ensure's an email address format is valid.
func validateEmail(user *auth.User) error {
	email := user.Email.String
	if email == "" {
		return nil
	}

	if !contactchecker.IsEmailValid(email) {
		return auth.ErrInvalidField("email address is invalid")
	}

	return nil
}

// validatePhone ensure's a phone number is valid.
func validatePhone(user *auth.User) error {
	phone := user.Phone.String
	if phone == "" {
		return nil
	}

	if !contactchecker.IsPhoneValid(phone) {
		return auth.ErrInvalidField("phone number is invalid")
	}

	return nil
}

// validateUserUnverified ensure's a user is in an unverified state.
func validateUserUnverified(user *auth.User) error {
	if user.IsVerified {
		// External users should not be aware if a user is verified or not.
		// This error should not occur under normal conditions and the most
		// likely scenario is a race condition between legitimate and illegitimate
		// users in which one user completes account verification immediately before
		// another user obtains a lock before re-creation. In this case it
		// should be  treated as an internal error to prevent clients
		// from becoming aware of what users exist in our system.
		return fmt.Errorf("cannot re-create already verified user")
	}

	return nil
}

func sanitizeUser(user *auth.User) {
	user.Phone.String = strings.TrimSpace(user.Phone.String)
	user.Email.String = strings.ToLower(strings.TrimSpace(user.Email.String))
}
