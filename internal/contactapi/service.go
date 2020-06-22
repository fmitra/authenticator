// Package contactapi provides an HTTP API for email/SMS OTP management.
package contactapi

import (
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	otp      auth.OTPService
	message  auth.MessagingService
	repoMngr auth.RepositoryManager
}

// CheckAddress requests an OTP code to be delivered to the user through a
// email address or phone number so may we verify the user's ownership of the
// address.
func (s *service) CheckAddress(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Disable dissables a verified email or phone number from receiving OTP codes in
// the future.
func (s *service) Disable(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Verify verifies an OTP code sent to an email or phone number. If the delivery
// address is new to the user, it will be set on the profile. By default, verified
// addresses are enabled for future OTP code delivery unless the client explicitly
// says otherwise.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Remove removes a verified email or phone number from the User's profile. Removed
// addresses must be re-verified with an OTP code in order to be set back onto the
// profile.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Send allows a user to request an OTP code to be delivered to them through a
// pre-approved channel. Verified users may only have a code delivered through an
// address on file that they have previously enabled for OTP delivery. Unverified
// or new users initiating signup may only request delivery through the phone/email
// used in signup.
func (s *service) Send(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}
