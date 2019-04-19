package webauthn

import (
	webauthnLib "github.com/duo-labs/webauthn/webauthn"

	auth "github.com/fmitra/authenticator"
)

// User is a wrapper for the authenticator domain entity auth.User
// to allow compatibility with duo-lab's webauthn User interface.
type User struct {
	auth.User
	Devices []*auth.Device
}

// WebAuthnID returns the User's ID.
func (u *User) WebAuthnID() []byte {
	return []byte("")
}

// WebAuthnName returns the User's name.
func (u *User) WebAuthnName() string {
	displayName := u.Email.String
	if u.Email.String == "" {
		displayName = u.Phone.String
	}
	return displayName
}

// WebAuthnDisplayName returns the User's display name.
func (u *User) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

// WebAuthnIcon returns an Icon for the user.
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns all of the user's Devices.
func (u *User) WebAuthnCredentials() []webauthnLib.Credential {
	totalDevices := len(u.Devices)

	var wcs []webauthnLib.Credential
	{
		wcs = make([]webauthnLib.Credential, totalDevices)

		for idx, device := range u.Devices {
			credential := webauthnLib.Credential{
				ID:        device.ClientID,
				PublicKey: device.PublicKey,
				Authenticator: webauthnLib.Authenticator{
					AAGUID:    device.AAGUID,
					SignCount: device.SignCount,
				},
			}

			wcs[idx] = credential
		}
	}

	return wcs
}
