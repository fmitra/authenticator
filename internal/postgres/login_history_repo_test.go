package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/oklog/ulid/v2"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestLoginHistoryRepository_ByTokenID(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	tokenID, err := ulid.New(ulid.Now(), c.entropy)
	if err != nil {
		t.Fatal("failed to generate token ID:", err)
	}

	login := auth.LoginHistory{
		UserID:    user.ID,
		TokenID:   tokenID.String(),
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Minute * 30),
	}
	err = c.LoginHistory().Create(ctx, &login)
	if err != nil {
		t.Fatal("failed to create LoginHistory:", err)
	}

	fetchedLogin, err := c.LoginHistory().ByTokenID(ctx, tokenID.String())
	if err != nil {
		t.Fatal("failed to retrieve LoginHistory:", err)
	}

	if !cmp.Equal(fetchedLogin.TokenID, login.TokenID) {
		t.Error("LoginHistory.ID does not match", cmp.Diff(
			fetchedLogin.TokenID, login.TokenID,
		))
	}
}

func TestLoginHistoryRepository_Create(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	tokenID, err := ulid.New(ulid.Now(), c.entropy)
	if err != nil {
		t.Fatal("failed to generate token ID:", err)
	}

	login := auth.LoginHistory{
		UserID:    user.ID,
		TokenID:   tokenID.String(),
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Minute * 30),
	}
	err = c.LoginHistory().Create(ctx, &login)
	if err != nil {
		t.Fatal("failed to create loginhistory:", err)
	}

	now := time.Now()
	if (now.Sub(login.CreatedAt)).Seconds() > 1 {
		t.Errorf("%s is not a valid time generated for CreatedAt", login.CreatedAt)
	}
	if (now.Sub(login.UpdatedAt)).Seconds() > 1 {
		t.Errorf("%s is not a valid timestamp for UpdatedAt", login.UpdatedAt)
	}
}

func TestLoginHistoryRepository_ByUserID(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	for i := 0; i < 19; i++ {
		tokenID, err := ulid.New(ulid.Now(), c.entropy)
		if err != nil {
			t.Fatal("failed to generate token ID:", err)
		}

		login := auth.LoginHistory{
			UserID:    user.ID,
			TokenID:   tokenID.String(),
			IsRevoked: false,
			ExpiresAt: time.Now().Add(time.Minute * 30),
		}
		err = c.LoginHistory().Create(ctx, &login)
		if err != nil {
			t.Fatal("failed to create loginhistory:", err)
		}
	}

	tt := []struct {
		limit      int
		offset     int
		resultSize int
		name       string
	}{
		{
			name:       "Paginate page 1",
			limit:      10,
			offset:     0,
			resultSize: 10,
		},
		{
			name:       "Paginate page 2",
			limit:      10,
			offset:     10,
			resultSize: 9,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			logins, err := c.LoginHistory().ByUserID(ctx, user.ID, tc.limit, tc.offset)
			if err != nil {
				t.Fatal("failed to retrieve loginhistory:", err)
			}

			if len(logins) != tc.resultSize {
				t.Errorf("incorrect number of logins: want %v got %v",
					tc.resultSize, len(logins))
			}
		})
	}
}

func TestLoginHistoryRepository_Update(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	tokenID, err := ulid.New(ulid.Now(), c.entropy)
	if err != nil {
		t.Fatal("failed to generate token ID:", err)
	}

	login := auth.LoginHistory{
		UserID:    user.ID,
		TokenID:   tokenID.String(),
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Minute * 30),
	}
	err = c.LoginHistory().Create(ctx, &login)
	if err != nil {
		t.Fatal("failed to create loginhistory:", err)
	}

	client, err := c.NewWithTransaction(ctx)
	if err != nil {
		t.Fatal("failed to start transaction:", err)
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		login, err := client.LoginHistory().GetForUpdate(ctx, login.TokenID)
		if err != nil {
			return nil, err
		}

		login.IsRevoked = true
		err = client.LoginHistory().Update(ctx, login)
		if err != nil {
			return nil, err
		}
		return login, nil
	})
	if err != nil {
		t.Fatal("failed to update loginhistory:", err)
	}

	updatedLogin := entity.(*auth.LoginHistory)
	if !updatedLogin.IsRevoked {
		t.Errorf("login status is not updated: want %v got %v",
			true, updatedLogin.IsRevoked)
	}
	if updatedLogin.TokenID != login.TokenID {
		t.Errorf("login IDs do not match: want %s got %s",
			login.TokenID, updatedLogin.TokenID)
	}
}
