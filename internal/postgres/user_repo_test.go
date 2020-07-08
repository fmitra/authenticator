package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/oklog/ulid"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/test"
)

func TestUserRepository_Create(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	tt := []struct {
		name      string
		email     sql.NullString
		phone     sql.NullString
		password  string
		isCreated bool
	}{
		{
			name:      "No phone or email failure",
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
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	c := TestClient(pgDB.DB)

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
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
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()
	c := TestClient(pgDB.DB)

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
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

func TestUserRepository_ReCreateFailure(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()
	c := TestClient(pgDB.DB)

	tt := []struct {
		name        string
		email       sql.NullString
		phone       sql.NullString
		password    string
		isDomainErr bool
		isVerified  bool
	}{
		{
			name:        "No phone or email failure",
			email:       sql.NullString{},
			phone:       sql.NullString{},
			password:    "swordfish",
			isDomainErr: true,
			isVerified:  false,
		},
		{
			name: "Invalid email failure",
			email: sql.NullString{
				String: "not-a-real-email",
				Valid:  true,
			},
			phone:       sql.NullString{},
			password:    "swordfish",
			isDomainErr: true,
			isVerified:  false,
		},
		{
			name:  "Invalid phone failure",
			email: sql.NullString{},
			phone: sql.NullString{
				String: "94867353",
				Valid:  true,
			},
			password:    "swordfish",
			isDomainErr: true,
			isVerified:  false,
		},
		{
			name: "Fail if password invalid",
			email: sql.NullString{
				String: "jane@example.com",
				Valid:  true,
			},
			phone:       sql.NullString{},
			password:    "short",
			isDomainErr: true,
			isVerified:  false,
		},
		{
			name: "Already verified failure",
			email: sql.NullString{
				String: "jane@example.com",
				Valid:  true,
			},
			phone:       sql.NullString{},
			password:    "swordfish",
			isDomainErr: false,
			isVerified:  true,
		},
	}

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		Phone: sql.NullString{
			String: "+6594867353",
			Valid:  true,
		},
		IsVerified: true,
	}
	ctx := context.Background()
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			newUser := auth.User{
				ID:         user.ID,
				Password:   tc.password,
				TFASecret:  "tfa_secret",
				Email:      tc.email,
				Phone:      tc.phone,
				IsVerified: tc.isVerified,
			}
			err = c.User().ReCreate(ctx, &newUser)
			if err == nil {
				t.Fatal("new user should not be created")
			}

			if tc.isDomainErr && auth.DomainError(err) == nil {
				t.Error("user creation should be blocked by domain error")
			}
		})
	}
}

func TestUserRepository_ReCreateSuccess(t *testing.T) {
	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()
	c := TestClient(pgDB.DB)

	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		Phone: sql.NullString{
			String: "+6594867353",
			Valid:  true,
		},
		IsVerified: false,
	}
	ctx := context.Background()
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	newUser := auth.User{
		ID:        user.ID,
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		Phone: sql.NullString{
			String: "+6594867353",
			Valid:  true,
		},
	}

	err = c.User().ReCreate(ctx, &newUser)
	if err != nil {
		t.Fatal("failed to re-create user:", err)
	}

	if user.ID == newUser.ID {
		t.Error("recreated user should have newly generated ID")
	}

	if newUser.CreatedAt.Unix() < user.CreatedAt.Unix() {
		t.Error("new user should be created after the older user")
	}
}

func TestUserRepository_DisableOTP(t *testing.T) {
	tt := []struct {
		name           string
		user           auth.User
		deliveryMethod auth.DeliveryMethod
		isPhoneAllowed bool
		isEmailAllowed bool
		hasError       bool
	}{
		{
			name: "Requires at least one 2FA",
			user: auth.User{
				Password:          "swordfish",
				IsEmailOTPAllowed: true,
				IsPhoneOTPAllowed: false,
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			deliveryMethod: auth.Email,
			isPhoneAllowed: false,
			isEmailAllowed: true,
			hasError:       true,
		},
		{
			name: "Disable phone OTP",
			user: auth.User{
				Password:          "swordfish",
				IsEmailOTPAllowed: false,
				IsPhoneOTPAllowed: true,
				IsTOTPAllowed:     true,
				Phone: sql.NullString{
					String: "+639455189172",
					Valid:  true,
				},
			},
			deliveryMethod: auth.Phone,
			isPhoneAllowed: false,
			isEmailAllowed: false,
			hasError:       false,
		},
		{
			name: "Disable email OTP",
			user: auth.User{
				Password:          "swordfish",
				IsEmailOTPAllowed: true,
				IsPhoneOTPAllowed: false,
				IsTOTPAllowed:     true,
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			deliveryMethod: auth.Email,
			isPhoneAllowed: false,
			isEmailAllowed: false,
			hasError:       false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()
			c := TestClient(pgDB.DB)

			ctx := context.Background()
			err = c.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			_, err = c.User().DisableOTP(ctx, tc.user.ID, tc.deliveryMethod)
			if !tc.hasError && err != nil {
				t.Error("expected nil error, received:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}

			user, err := c.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Fatal("failed to retrieve test user:", err)
			}

			if !cmp.Equal(user.IsPhoneOTPAllowed, tc.isPhoneAllowed) {
				t.Error(cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneAllowed))
			}

			if !cmp.Equal(user.IsEmailOTPAllowed, tc.isEmailAllowed) {
				t.Error(cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailAllowed))
			}
		})
	}
}

func TestUserRepository_RemoveDeliveryMethod(t *testing.T) {
	tt := []struct {
		name           string
		email          string
		phone          string
		user           auth.User
		deliveryMethod auth.DeliveryMethod
		isPhoneAllowed bool
		isEmailAllowed bool
		hasError       bool
	}{
		{
			name: "Requires at least one contact",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			phone:          "",
			email:          "jane@example.com",
			deliveryMethod: auth.Email,
			isPhoneAllowed: false,
			isEmailAllowed: true,
			hasError:       true,
		},
		{
			name: "Remove phone",
			user: auth.User{
				Password: "swordfish",
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				Phone: sql.NullString{
					String: "+639455189172",
					Valid:  true,
				},
			},
			email:          "jane@example.com",
			phone:          "",
			deliveryMethod: auth.Phone,
			isPhoneAllowed: false,
			isEmailAllowed: true,
			hasError:       false,
		},
		{
			name: "Remove email",
			user: auth.User{
				Password: "swordfish",
				Phone: sql.NullString{
					String: "+639455189172",
					Valid:  true,
				},
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
			},
			email:          "",
			phone:          "+639455189172",
			deliveryMethod: auth.Email,
			isPhoneAllowed: true,
			isEmailAllowed: false,
			hasError:       false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()
			c := TestClient(pgDB.DB)

			ctx := context.Background()
			err = c.User().Create(ctx, &tc.user)
			if err != nil {
				t.Fatal("failed to create user:", err)
			}

			_, err = c.User().RemoveDeliveryMethod(ctx, tc.user.ID, tc.deliveryMethod)
			if !tc.hasError && err != nil {
				t.Error("expected nil error, received:", err)
			}
			if tc.hasError && err == nil {
				t.Error("expected error, not nil")
			}

			user, err := c.User().ByIdentity(ctx, "ID", tc.user.ID)
			if err != nil {
				t.Fatal("failed to retrieve test user:", err)
			}

			if !cmp.Equal(user.Email.String, tc.email) {
				t.Error(cmp.Diff(user.Email.String, tc.email))
			}

			if !cmp.Equal(user.Phone.String, tc.phone) {
				t.Error(cmp.Diff(user.Phone.String, tc.phone))
			}

			if !cmp.Equal(user.IsPhoneOTPAllowed, tc.isPhoneAllowed) {
				t.Error(cmp.Diff(user.IsPhoneOTPAllowed, tc.isPhoneAllowed))
			}

			if !cmp.Equal(user.IsEmailOTPAllowed, tc.isEmailAllowed) {
				t.Error(cmp.Diff(user.IsEmailOTPAllowed, tc.isEmailAllowed))
			}
		})
	}
}
