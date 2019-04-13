package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/oklog/ulid"

	auth "github.com/fmitra/authenticator"
)

func TestUserRepository_Create(t *testing.T) {
	c, err := NewTestClient("user_repo_create_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "user_repo_create_test")

	tt := []struct {
		name      string
		email     sql.NullString
		phone     sql.NullString
		password  string
		isCreated bool
	}{
		{
			name:      "No phone/email failure",
			email:     sql.NullString{},
			phone:     sql.NullString{},
			password:  "swordfish",
			isCreated: false,
		},
		{
			name: "Invalid email failure",
			email: sql.NullString{
				String: "not-a-real-email",
				Valid:  true,
			},
			phone:     sql.NullString{},
			password:  "swordfish",
			isCreated: false,
		},
		{
			name:  "Invalid phone failure",
			email: sql.NullString{},
			phone: sql.NullString{
				String: "94867353",
				Valid:  true,
			},
			password:  "swordfish",
			isCreated: false,
		},
		{
			name:  "Valid phone success",
			email: sql.NullString{},
			phone: sql.NullString{
				String: "+6594867353",
				Valid:  true,
			},
			password:  "swordfish",
			isCreated: true,
		},
		{
			name: "Valid email success",
			email: sql.NullString{
				String: "jane@example.com",
				Valid:  true,
			},
			phone:     sql.NullString{},
			password:  "swordfish",
			isCreated: true,
		},
		{
			name: "Fail if password invalid",
			email: sql.NullString{
				String: "jane@example.com",
				Valid:  true,
			},
			phone:     sql.NullString{},
			password:  "short",
			isCreated: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			user := auth.User{
				Password:  tc.password,
				TFASecret: "tfa_secret",
				AuthReq:   auth.RequirePassword,
				Email:     tc.email,
				Phone:     tc.phone,
			}
			ctx := context.Background()
			err = c.User().Create(ctx, &user)
			if tc.isCreated && err != nil {
				t.Fatal("failed to create user:", err)
			}

			if !tc.isCreated && auth.DomainError(err) == nil {
				t.Error("user creation should be blocked by domain error")
			}

			if !tc.isCreated {
				return
			}

			now := time.Now()
			if (now.Sub(user.CreatedAt)).Seconds() > 1 {
				t.Errorf("%s is not a valid time generated for CreatedAt", user.CreatedAt)
			}
			if (now.Sub(user.UpdatedAt)).Seconds() > 1 {
				t.Errorf("%s is not a valid timestamp for UpdatedAt", user.UpdatedAt)
			}

			_, err = ulid.Parse(user.ID)
			if err != nil {
				t.Error("invalid ID generated for user:", err)
			}
		})
	}
}

func TestUserRepository_ByIdentity(t *testing.T) {
	c, err := NewTestClient("user_repo_by_identity_test")
	if err != nil {
		t.Fatal(err, "failed to create test database")
	}
	defer DropTestDB(c, "user_repo_by_identity_test")

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Phone: sql.NullString{
			String: "+6590000000",
			Valid:  true,
		},
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	ctx := context.Background()
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	tt := []struct {
		name        string
		searchField string
		searchValue string
		hasError    bool
	}{
		{
			name:        "Search by ID",
			searchField: "ID",
			searchValue: user.ID,
			hasError:    false,
		},
		{
			name:        "Search by phone",
			searchField: "Phone",
			searchValue: user.Phone.String,
			hasError:    false,
		},
		{
			name:        "Search by email",
			searchField: "Email",
			searchValue: user.Email.String,
			hasError:    false,
		},
		{
			name:        "Search by email failure",
			searchField: "Email",
			searchValue: "doesnotexist@example.com",
			hasError:    true,
		},
		{
			name:        "Search by password",
			searchField: "Email",
			searchValue: "swordfish",
			hasError:    true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			userB, err := c.User().ByIdentity(ctx, tc.searchField, tc.searchValue)
			if !tc.hasError && err != nil {
				t.Error("failed to find user:", err)
			}
			if !tc.hasError && userB.ID != user.ID {
				t.Errorf("user IDs do not match: want %s got %s", user.ID, userB.ID)
			}
			if tc.hasError && err == nil {
				t.Error("expected error on user retrieval")
			}
		})
	}
}

func TestUserRepository_Update(t *testing.T) {
	c, err := NewTestClient("user_repo_update_test")
	if err != nil {
		t.Fatal(err, "failed to create test database")
	}
	defer DropTestDB(c, "user_repo_update_test")

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	ctx := context.Background()
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	client, err := c.NewWithTransaction(ctx)
	if err != nil {
		t.Fatal("failed to start transaction:", err)
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		user, err := client.User().GetForUpdate(ctx, user.ID)
		if err != nil {
			return nil, err
		}

		user.Email = sql.NullString{
			String: "john@example.com",
			Valid:  true,
		}
		err = client.User().Update(ctx, user)
		if err != nil {
			return nil, err
		}
		return user, nil
	})
	if err != nil {
		t.Fatal("failed to update user:", err)
	}

	updatedUser := entity.(*auth.User)
	if updatedUser.Email.String != "john@example.com" {
		t.Errorf("user email is not updated: want %s got %s",
			"john@example.com", updatedUser.Email.String)
	}
	if user.ID != updatedUser.ID {
		t.Errorf("user IDs do not match: want %s got %s",
			user.ID, updatedUser.ID)
	}
}
