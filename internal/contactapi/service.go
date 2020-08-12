// Package contactapi provides an HTTP API for email/SMS OTP management.
package contactapi

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"

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

	token := httpapi.GetToken(r)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithOTPDeliveryMethod(req.DeliveryMethod),
		tokenLib.WithOTPAddress(req.Address),
		tokenLib.WithRefreshableToken(token),
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
		return nil, fmt.Errorf("invalid OTP created: %w", err)
	}

	msg := &auth.Message{
		Type: auth.OTPAddress,
		Delivery: h.DeliveryMethod,
		Vars: map[string]string{"code": token.Code},
		Address: h.Address,
	}
	if err = s.message.Send(ctx, msg); err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
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

	user, err := s.repoMngr.User().DisableOTP(ctx, userID, req.DeliveryMethod)
	if err != nil {
		return nil, err
	}

	token := httpapi.GetToken(r)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithRefreshableToken(token),
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
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

	entity, err := txClient.WithAtomic(func() (interface{}, error) {
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
		return nil, fmt.Errorf(
			"%v: %w",
			err,
			auth.ErrBadRequest("sorry we can't update your contact details"),
		)
	}

	user := entity.(*auth.User)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithRefreshableToken(token),
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
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

	user, err := s.repoMngr.User().RemoveDeliveryMethod(ctx, userID, req.DeliveryMethod)
	if err != nil {
		return nil, err
	}

	token := httpapi.GetToken(r)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithRefreshableToken(token),
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
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

	token := httpapi.GetToken(r)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTPreAuthorized,
		tokenLib.WithOTPDeliveryMethod(req.DeliveryMethod),
		tokenLib.WithRefreshableToken(token),
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
		return nil, fmt.Errorf("invalid OTP created: %w", err)
	}

	msg := &auth.Message{
		Type: auth.OTPResend,
		Vars: map[string]string{"code": token.Code},
		Address: h.Address,
		Delivery: h.DeliveryMethod,
	}
	if err = s.message.Send(ctx, msg); err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
}
