// Package contactchecker offers utility functions for validating
// addresses.
package contactchecker

import (
	"net/mail"

	"github.com/nyaruka/phonenumbers"

	auth "github.com/fmitra/authenticator"
)

// IsPhoneValid checks if a phone string is a valid format.
func IsPhoneValid(phone string) bool {
	// We expect phone numbers to be supplied with valid country
	// codes. Due to this, we leave country ISO values blank.
	countryISO := ""
	meta, err := phonenumbers.Parse(phone, countryISO)
	if err != nil {
		return false
	}

	return phonenumbers.IsValidNumber(meta)
}

// IsEmailValid checks if an email string is a valid format.
func IsEmailValid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Validator returns ane mail or phoen validator.
func Validator(method auth.DeliveryMethod) func(s string) bool {
	if method == auth.Email {
		return IsEmailValid
	}

	if method == auth.Phone {
		return IsPhoneValid
	}

	return func(s string) bool {
		return false
	}
}
