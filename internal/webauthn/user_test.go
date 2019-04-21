package webauthn

import (
	"bytes"
	"database/sql"
	"reflect"
	"testing"

	webauthnLib "github.com/duo-labs/webauthn/webauthn"

	auth "github.com/fmitra/authenticator"
)

func TestWebAuthnUser_UserMeetsInterfaceSpec(t *testing.T) {
	tt := []struct {
		name     string
		email    string
		phone    string
		userName string
	}{
		{
			name:     "Valid email",
			email:    "jane@example.com",
			phone:    "",
			userName: "jane@example.com",
		},
		{
			name:     "Valid phone",
			email:    "",
			phone:    "+15555555555",
			userName: "+15555555555",
		},
		{
			name:     "Defaults to email",
			email:    "jane@example.com",
			phone:    "+15555555555",
			userName: "jane@example.com",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			domainUser := &auth.User{
				ID: "unique-user-id",
				Email: sql.NullString{
					String: tc.email,
					Valid:  true,
				},
				Phone: sql.NullString{
					String: tc.phone,
					Valid:  true,
				},
			}
			devices := []*auth.Device{
				{
					ID:        "unique-device-id",
					ClientID:  []byte("client-supplied-id"),
					PublicKey: []byte("device-public-key"),
					AAGUID:    []byte("device-aaguid"),
					SignCount: uint32(3),
				},
			}
			credentials := []webauthnLib.Credential{
				{
					ID:        []byte("client-supplied-id"),
					PublicKey: []byte("device-public-key"),
					Authenticator: webauthnLib.Authenticator{
						AAGUID:    []byte("device-aaguid"),
						SignCount: uint32(3),
					},
				},
			}

			user := User{
				User:    domainUser,
				Devices: devices,
			}
			if !bytes.Equal([]byte(domainUser.ID), user.WebAuthnID()) {
				t.Errorf("user ID is not equal, want %v got %v",
					domainUser.ID, string(user.WebAuthnID()))
			}
			if user.WebAuthnName() != tc.userName {
				t.Errorf("user webauthn name is not equal, want %s got %s",
					tc.userName, user.WebAuthnName())
			}
			if user.WebAuthnDisplayName() != tc.userName {
				t.Errorf("user webauthn name is not equal, want %s got %s",
					tc.userName, user.WebAuthnDisplayName())
			}
			if user.WebAuthnIcon() != "" {
				t.Errorf("user icon should be blank, received %s", user.WebAuthnIcon())
			}
			if !reflect.DeepEqual(user.WebAuthnCredentials(), credentials) {
				t.Errorf("user credentials do not match, want %v got %v",
					credentials, user.WebAuthnCredentials())
			}
		})
	}
}
