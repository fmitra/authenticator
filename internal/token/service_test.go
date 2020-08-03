package token

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/oklog/ulid/v2"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/crypto"
	"github.com/fmitra/authenticator/internal/otp"
	"github.com/fmitra/authenticator/internal/postgres"
	"github.com/fmitra/authenticator/internal/test"
)

func NewTestTokenSvc(db Rediser, repoMngr auth.RepositoryManager) auth.TokenService {
	tokenSvc := NewService(
		WithLogger(log.NewNopLogger()),
		WithDB(db),
		WithTokenExpiry(time.Second*10),
		WithSecret("my-signing-secret"),
		WithIssuer("authenticator"),
		WithOTP(otp.NewOTP()),
		WithCookieDomain("authenticator.local"),
		WithCookieMaxAge(1000),
		WithRepoManager(repoMngr),
	)

	return tokenSvc
}

func TestTokenSvc_CreateAuthorized(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	now := time.Now().Unix()
	later := time.Now().Add(time.Second * 8).Unix()
	expiry := time.Now().Add(time.Second * 10).Unix()
	if token.ExpiresAt < now {
		t.Error("token expiry cannot be earlier than current time")
	}
	if token.ExpiresAt < later {
		t.Error("token expiry cannot be earlier than 8 seconds from now")
	}
	if token.ExpiresAt > expiry {
		t.Error("token should expiry by 10 seconds")
	}

	_, err = ulid.Parse(token.Id)
	if err != nil {
		t.Error("invalid ID generated for token")
	}

	if token.ClientID == "" || token.ClientIDHash == "" {
		t.Error("invalid clientID generated for token")
	}

	if token.Code != "" || token.CodeHash != "" {
		t.Error("otp code generation should be optional")
	}

	if token.RefreshToken == "" || token.RefreshTokenHash == "" {
		t.Error("invalid refresh token generated")
	}

	if token.State != auth.JWTAuthorized {
		t.Error("state does not match", cmp.Diff(
			token.State, auth.JWTAuthorized,
		))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.ClientID)
	if err != nil {
		t.Error("failed to decode client ID:", err)
	}

	clientIDHash, err := crypto.Hash(string(decoded))
	if err != nil {
		t.Error("failed to create client ID hash:", err)
	}

	if !cmp.Equal(clientIDHash, token.ClientIDHash) {
		t.Error("client ID does not match", cmp.Diff(
			clientIDHash, token.ClientIDHash,
		))
	}

	decoded, err = base64.RawURLEncoding.DecodeString(token.RefreshToken)
	if err != nil {
		t.Error("failed to decode refresh token:", err)
	}

	refreshTokenHash, err := crypto.Hash(string(decoded))
	if err != nil {
		t.Error("failed to create refresh token hash:", err)
	}

	if !cmp.Equal(refreshTokenHash, token.RefreshTokenHash) {
		t.Error("refresh token does not match", cmp.Diff(
			refreshTokenHash, token.RefreshTokenHash,
		))
	}
}

func TestTokenSvc_CreatePreAuthorized(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id", IsEmailOTPAllowed: true}
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	token, err := tokenSvc.Create(ctx, user, auth.JWTPreAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	if token.State != auth.JWTPreAuthorized {
		t.Error("state does not match", cmp.Diff(
			token.State, auth.JWTPreAuthorized,
		))
	}
}

func TestTokenSvc_CreateWithTFAOptions(t *testing.T) {
	tt := []struct {
		name       string
		user       auth.User
		tfaOptions []auth.TFAOptions
	}{
		{
			name: "Support Email OTP delivery",
			user: auth.User{
				ID:                "user_id",
				IsEmailOTPAllowed: true,
			},
			tfaOptions: []auth.TFAOptions{
				auth.OTPEmail,
			},
		},
		{
			name: "Support Phone OTP Delivery",
			user: auth.User{
				ID:                "user_id",
				IsPhoneOTPAllowed: true,
			},
			tfaOptions: []auth.TFAOptions{
				auth.OTPPhone,
			},
		},
		{
			name: "Support TOTP",
			user: auth.User{
				ID:            "user_id",
				IsTOTPAllowed: true,
			},
			tfaOptions: []auth.TFAOptions{
				auth.TOTP,
			},
		},
		{
			name: "Support FIDO devices",
			user: auth.User{
				ID:              "user_id",
				IsDeviceAllowed: true,
			},
			tfaOptions: []auth.TFAOptions{
				auth.FIDODevice,
			},
		},
	}

	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

			token, err := tokenSvc.Create(ctx, &tc.user, auth.JWTAuthorized)
			if err != nil {
				t.Fatal("failed to create token", err)
			}

			if !cmp.Equal(token.TFAOptions, tc.tfaOptions) {
				t.Error("TFAOPtions does not match", cmp.Diff(
					token.TFAOptions, tc.tfaOptions,
				))
			}
		})
	}
}

func TestTokenSvc_CreateWithOTP(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{
		ID:                "user_id",
		IsPhoneOTPAllowed: true,
		Phone: sql.NullString{
			String: "+15555555555",
			Valid:  true,
		},
	}
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	token, err := tokenSvc.Create(
		ctx,
		user,
		auth.JWTPreAuthorized,
		WithOTPDeliveryMethod(auth.Phone),
	)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	if token.Code == "" || token.CodeHash == "" {
		t.Error("otp codes should be generated for pre-authorized tokens")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.CodeHash)
	if err != nil {
		t.Error("failed to decode code hash:", err)
	}

	var o otp.Hash
	err = json.Unmarshal(decoded, &o)
	if err != nil {
		t.Error("failed to unmarshal code hash:", err)
	}

	if o.DeliveryMethod != auth.Phone {
		t.Error("otp delivery does not match", cmp.Diff(
			o.DeliveryMethod, auth.Phone,
		))
	}
}

func TestTokenSvc_CreateWithOTPAndAddress(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{
		ID:                "user_id",
		IsEmailOTPAllowed: true,
		IsPhoneOTPAllowed: false,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	token, err := tokenSvc.Create(
		ctx,
		user,
		auth.JWTPreAuthorized,
		WithOTPDeliveryMethod(auth.Phone),
		WithOTPAddress("+6594867353"),
	)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	if token.Code == "" || token.CodeHash == "" {
		t.Error("otp codes should be generated for pre-authorized tokens")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.CodeHash)
	if err != nil {
		t.Error("failed to decode code hash:", err)
	}

	var o otp.Hash
	err = json.Unmarshal(decoded, &o)
	if err != nil {
		t.Error("failed to unmarshal code hash:", err)
	}

	if o.Address != "+6594867353" {
		t.Error("otp address does not match", cmp.Diff(
			o.Address, "+6594867353",
		))
	}
}

func TestTokenSvc_InvalidateAfterRevocation(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	pgDB, err := test.NewPGDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pgDB.DropDB()

	repoMngr := postgres.TestClient(pgDB.DB)
	ctx := context.Background()
	user := &auth.User{
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
		Password: "swordfish",
	}
	err = repoMngr.User().Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create test user", err)
	}

	tokenSvc := NewTestTokenSvc(db, repoMngr)

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	err = repoMngr.LoginHistory().Create(ctx, &auth.LoginHistory{
		TokenID:   token.Id,
		UserID:    user.ID,
		IsRevoked: false,
	})
	if err != nil {
		t.Fatal("failed to create login history", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	jwtToken = fmt.Sprintf("Bearer %s", jwtToken)
	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err != nil {
		t.Error("failed to validate token:", err)
	}

	err = tokenSvc.Revoke(ctx, token.Id)
	if err != nil {
		t.Error("failed to revoke token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err == nil {
		t.Fatal("revoked token should return error")
	}

	code := auth.ErrorCode(err)
	if code != auth.EInvalidToken {
		t.Errorf("incorrect error code: want %s got %s",
			auth.EInvalidToken, code)
	}

	loginHistory, err := repoMngr.LoginHistory().ByTokenID(ctx, token.Id)
	if err != nil {
		t.Fatal("no login history record found", err)
	}

	if !loginHistory.IsRevoked {
		t.Error("login history was not revoked")
	}
}

func TestTokenSvc_InvalidateAfterExpiry(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}

	tokenSvc := NewService(
		WithDB(db),
		WithTokenExpiry(time.Millisecond),
		WithSecret("my-signing-secret"),
		WithIssuer("authenticator"),
		WithOTP(otp.NewOTP()),
	)

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	jwtToken = fmt.Sprintf("Bearer %s", jwtToken)
	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err != nil {
		t.Error("failed to validate token:", err)
	}

	time.Sleep(time.Second)
	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err == nil {
		t.Error("expired token should return error")
	}
}

func TestTokenSvc_InvalidateNotBearer(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	_, err = tokenSvc.Validate(ctx, "jwt-token", "client-id")
	domainErr := auth.DomainError(err)
	if domainErr == nil {
		t.Fatal("expected domain error")
	}

	if domainErr.Code() != auth.EInvalidToken {
		t.Errorf("incorrect error code, want %s got %s",
			auth.EInvalidToken, domainErr.Code())
	}

	if domainErr.Message() != "bearer token expected" {
		t.Errorf("incorrect error code, want %s got %s",
			"bearer token expected", domainErr.Message())
	}
}

func TestTokenSvc_InvalidateNoUserID(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{}

	tokenSvc := NewService(
		WithDB(db),
		WithTokenExpiry(time.Millisecond),
		WithSecret("my-signing-secret"),
		WithIssuer("authenticator"),
		WithOTP(otp.NewOTP()),
	)

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err == nil {
		t.Error("token with no user ID should return error, not nil")
	}
}

func TestTokenSvc_InvalidateClientIDMismatch(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}

	tokenSvc := NewService(
		WithDB(db),
		WithTokenExpiry(time.Millisecond),
		WithSecret("my-signing-secret"),
		WithIssuer("authenticator"),
		WithOTP(otp.NewOTP()),
	)

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	jwtToken = fmt.Sprintf("Bearer %s", jwtToken)
	_, err = tokenSvc.Validate(ctx, jwtToken, token.ClientID)
	if err != nil {
		t.Error("failed to validate token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken, base64.RawURLEncoding.EncodeToString([]byte("bad-client-id")))
	domainErr := auth.DomainError(err)
	if domainErr == nil {
		t.Fatal("expected domain error")
	}

	if domainErr.Code() != auth.EInvalidToken {
		t.Errorf("incorrect error code, want %s got %s",
			auth.EInvalidToken, domainErr.Code())
	}
}

func TestTokenSvc_Refreshable(t *testing.T) {
	tt := []struct {
		name               string
		errCode            auth.ErrCode
		refreshTokenExpiry time.Duration
		isRevoked          bool
	}{
		{
			name:               "Validates refreshable token",
			refreshTokenExpiry: time.Minute * 2,
			errCode:            auth.ErrCode(""),
			isRevoked:          false,
		},
		{
			name:               "Invalidates expired refreshable token",
			errCode:            auth.EInvalidToken,
			refreshTokenExpiry: time.Millisecond,
			isRevoked:          false,
		},
		{
			name:               "Invalidates revoked refreshable token",
			errCode:            auth.EInvalidToken,
			refreshTokenExpiry: time.Minute * 2,
			isRevoked:          true,
		},
	}
	for idx, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			pgDB, err := test.NewPGDB()
			if err != nil {
				t.Fatal("failed to create test database:", err)
			}
			defer pgDB.DropDB()

			repoMngr := postgres.TestClient(pgDB.DB)
			ctx := context.Background()

			user := &auth.User{
				Email: sql.NullString{
					String: "jane@example.com",
					Valid:  true,
				},
				Password: "swordfish",
			}
			err = repoMngr.User().Create(ctx, user)
			if err != nil {
				t.Fatal("failed to create test user", err)
			}

			tokenSvc := &service{
				refreshTokenExpiry: tc.refreshTokenExpiry,
				repoMngr:           repoMngr,
			}
			token := &auth.Token{
				StandardClaims: jwt.StandardClaims{
					Id: fmt.Sprintf("%v", idx),
				},
			}

			err = repoMngr.LoginHistory().Create(ctx, &auth.LoginHistory{
				TokenID:   token.Id,
				UserID:    user.ID,
				IsRevoked: tc.isRevoked,
			})
			if err != nil {
				t.Fatal("failed to create login history", err)
			}

			refreshToken, refreshTokenHash, err := tokenSvc.genRefreshTokenAndHash(&auth.TokenConfiguration{})
			if err != nil {
				t.Fatal("failed to create refresh token")
			}

			token.RefreshTokenHash = refreshTokenHash

			err = tokenSvc.Refreshable(ctx, token, refreshToken)
			if !cmp.Equal(auth.ErrorCode(err), tc.errCode) {
				t.Error("error code does not match", cmp.Diff(
					auth.ErrorCode(err), tc.errCode,
				))
			}
		})
	}
}

func TestTokenSvc_InvalidatesOldTokensWithOTP(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	tokenSvc := NewTestTokenSvc(db, &test.RepositoryManager{})

	token, err := tokenSvc.Create(ctx, user, auth.JWTAuthorized,
		WithOTPDeliveryMethod(auth.Email),
		WithOTPAddress("jane@example.com"),
		WithRefreshableToken(&auth.Token{}),
	)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	ts, err := db.Get(ctx, invalidationKey(token.Id)).Int64()
	if err != nil {
		t.Fatal("no cached token found:", err)
	}

	if !cmp.Equal(ts, token.IssuedAt) {
		t.Error("invalidation cut off does not match issuing time", cmp.Diff(
			ts, token.IssuedAt,
		))
	}
}
