package pg

import (
	"context"
	"net/mail"
	"time"

	"github.com/nyaruka/phonenumbers"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

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
		return nil, errors.Errorf("%s is not a valid query paramter", attribute)
	}

	row := r.client.queryRowContext(ctx, r.client.userQ[q], value)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.IsCodeAllowed, &user.IsTOTPAllowed, &user.IsDeviceAllowed,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Create persists a new User to local storage.
func (r *UserRepository) Create(ctx context.Context, user *auth.User) error {
	err := validateUserFields(
		user,
		validateIdentity,
		validateEmail,
		validatePhone,
		validatePassword,
	)
	if err != nil {
		return err
	}

	userID, err := ulid.New(ulid.Now(), r.client.entropy)
	if err != nil {
		return errors.Wrap(err, "cannot generate unique user ID")
	}

	// bcrypt will manage its own salt
	// TODO Perhaps this should be done in the service layer.
	// Doing it here makes it impossible to check if a user is using the same password
	// You'll end up littering the passsword protocol accross service and repository
	// layers
	passwdHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "failed to hash password")
	}

	// TODO Generate user's TFA secret
	// TODO Handle users who attempt to-resign at a later time
	// for example, users who do not verify their phone/email
	// and attempt to create a new account. This should be an update
	// event where we hash the password and reset the created timestamp.
	// perhaps created time should reflect the validation date. this
	// would prevent users from re-setting the password with an email they
	// don't won prior to another user finishing validation
	user.Password = string(passwdHash)
	user.ID = userID.String()
	row := r.client.queryRowContext(
		ctx,
		r.client.userQ["insert"],
		user.ID,
		user.Phone,
		user.Email,
		user.Password,
		user.TFASecret,
		user.IsCodeAllowed,
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
		user.IsCodeAllowed,
		user.IsTOTPAllowed,
		user.IsDeviceAllowed,
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
		return errors.Errorf("wrong number of users updated: %d", updatedRows)
	}
	return nil
}

// GetForUpdate retrieves a User to be updated.
func (r *UserRepository) GetForUpdate(ctx context.Context, userID string) (*auth.User, error) {
	user := auth.User{}
	row := r.client.queryRowContext(ctx, r.client.userQ["forUpdate"], userID)
	err := row.Scan(
		&user.ID, &user.Phone, &user.Email, &user.Password, &user.TFASecret,
		&user.IsCodeAllowed, &user.IsTOTPAllowed, &user.IsDeviceAllowed,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
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

	_, err := mail.ParseAddress(email)
	if err != nil {
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

	// We expect phone numbers to be supplied with valid country
	// codes. Due to this, we leave country ISO values blank.
	countryISO := ""
	meta, err := phonenumbers.Parse(phone, countryISO)
	if err != nil {
		return auth.ErrInvalidField("phone number is invalid")
	}

	isValid := phonenumbers.IsValidNumber(meta)
	if !isValid {
		return auth.ErrInvalidField("phone number is invalid")
	}

	return nil
}

// validatePassword ensure's a password meets length requirements.
func validatePassword(user *auth.User) error {
	var (
		minPasswordLen = 8
		maxPasswordLen = 1000
	)

	if len(user.Password) < minPasswordLen {
		return auth.ErrInvalidField("password must be at least 8 characters long")
	}

	// A maximum password length is enforced to help mitigate DOS attacks.
	if len(user.Password) > maxPasswordLen {
		return auth.ErrInvalidField("password cannot be longer than 1000 characters")
	}

	return nil
}
