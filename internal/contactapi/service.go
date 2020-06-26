// Package contactapi provides an HTTP API for email/SMS OTP management.
package contactapi

import (
	"database/sql"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
	"github.com/fmitra/authenticator/internal/otp"
	tokenLib "github.com/fmitra/authenticator/internal/token"
)

type service struct {
	logger   log.Logger
	otp      auth.OTPService
	message  auth.MessagingService
	repoMngr auth.RepositoryManager
	token    auth.TokenService
}

// CheckAddress requests an OTP code to be delivered to the user through a
// email address or phone number so may we verify the user's ownership of the
// address.
func (s *service) CheckAddress(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	req, err := decodeDeliveryRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	token, err := s.token.CreateWithOTPAndAddress(
		ctx,
		user,
		auth.JWTAuthorized,
		req.DeliveryMethod,
		req.Address,
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	h, err := otp.FromOTPHash(token.CodeHash)
	if err != nil {
		return nil, errors.Wrap(err, "invalid OTP created")
	}

	if err = s.message.Send(ctx, token.Code, h.Address, h.DeliveryMethod); err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken, ClientID: token.ClientID}, nil
}

// Disable disables a verified email or phone number from receiving OTP codes in
// the future.
func (s *service) Disable(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	req, err := decodeDeactivateRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	_, err = s.repoMngr.User().DisableOTP(ctx, userID, req.DeliveryMethod)
	if err != nil {
		return nil, err
	}

	// TODO Return token after implementing token refresh
	return &tokenLib.Response{Token: "", ClientID: ""}, nil
}

// Verify verifies an OTP code sent to an email or phone number. If the delivery
// address is new to the user, it will be set on the profile. By default, verified
// addresses are enabled for future OTP code delivery unless the client explicitly
// says otherwise.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	req, err := decodeVerifyRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	userID := httpapi.GetUserID(r)
	token := httpapi.GetToken(r)

	if err = s.otp.ValidateOTP(req.Code, token.CodeHash); err != nil {
		return nil, err
	}

	otpHash, err := otp.FromOTPHash(token.CodeHash)
	if err != nil {
		return nil, err
	}

	txClient, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	_, err = txClient.WithAtomic(func() (interface{}, error) {
		user, err := txClient.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		if otpHash.DeliveryMethod == auth.Phone {
			user.Phone = sql.NullString{String: otpHash.Address, Valid: true}
			user.IsPhoneOTPAllowed = req.IsOTPEnabled
		}

		if otpHash.DeliveryMethod == auth.Email {
			user.Email = sql.NullString{String: otpHash.Address, Valid: true}
			user.IsEmailOTPAllowed = req.IsOTPEnabled
		}

		if err = txClient.User().Update(ctx, user); err != nil {
			return nil, err
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	// TODO Return token after implementing token refresh
	return &tokenLib.Response{Token: "", ClientID: ""}, nil
}

// Remove removes a verified email or phone number from the User's profile. Removed
// addresses must be re-verified with an OTP code in order to be set back onto the
// profile.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	req, err := decodeDeactivateRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	_, err = s.repoMngr.User().RemoveDeliveryMethod(ctx, userID, req.DeliveryMethod)
	if err != nil {
		return nil, err
	}

	// TODO Return token after implementing token refresh
	return &tokenLib.Response{Token: "", ClientID: ""}, nil
}

// Send allows a user to request an OTP code to be delivered to them through a
// pre-approved channel. Verified users may only have a code delivered through an
// address on file that they have previously enabled for OTP delivery. Unverified
// or new users initiating signup may only request delivery through the phone/email
// used in signup.
func (s *service) Send(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	req, err := decodeSendRequest(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	token, err := s.token.CreateWithOTP(
		ctx,
		user,
		auth.JWTPreAuthorized,
		req.DeliveryMethod,
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	h, err := otp.FromOTPHash(token.CodeHash)
	if err != nil {
		return nil, errors.Wrap(err, "invalid OTP created")
	}

	if err = s.message.Send(ctx, token.Code, h.Address, h.DeliveryMethod); err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken, ClientID: token.ClientID}, nil
}
