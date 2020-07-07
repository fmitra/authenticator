package token

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/oklog/ulid"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/otp"
	"github.com/fmitra/authenticator/internal/test"
)

func NewTestTokenSvc(db Rediser) auth.TokenService {
	var entropy io.Reader
	{
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		entropy = ulid.Monotonic(random, 0)
	}

	tokenSvc := NewService(
		WithLogger(log.NewNopLogger()),
		WithDB(db),
		WithEntropy(entropy),
		WithTokenExpiry(time.Second*10),
		WithSecret("my-signing-secret"),
		WithIssuer("authenticator"),
		WithOTP(otp.NewOTP()),
		WithCookieDomain("authenticator.local"),
		WithCookieMaxAge(1000),
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
	tokenSvc := NewTestTokenSvc(db)

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

	h := sha512.New()
	h.Write([]byte(token.ClientID))
	clientIDHash := hex.EncodeToString(h.Sum(nil))

	if !cmp.Equal(clientIDHash, token.ClientIDHash) {
		t.Error("client ID does not match", cmp.Diff(
			clientIDHash, token.ClientIDHash,
		))
	}

	h = sha512.New()
	h.Write([]byte(token.RefreshToken))
	refreshTokenHash := hex.EncodeToString(h.Sum(nil))

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
	tokenSvc := NewTestTokenSvc(db)

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
			tokenSvc := NewTestTokenSvc(db)

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
	tokenSvc := NewTestTokenSvc(db)

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

	splits := strings.Split(token.CodeHash, ":")
	if len(splits) != 4 {
		t.Fatal("incorrect segments in otp hash",
			cmp.Diff(len(splits), 4))
	}

	if splits[3] != "phone" {
		t.Error("otp delivery method does not match",
			cmp.Diff(splits[3], "phone"))
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
	tokenSvc := NewTestTokenSvc(db)

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

	splits := strings.Split(token.CodeHash, ":")
	if len(splits) != 4 {
		t.Fatal("incorrect segments in otp hash",
			cmp.Diff(len(splits), 4))
	}

	if splits[2] != "+6594867353" {
		t.Error("otp delivery address does not match",
			cmp.Diff(splits[2], "+6594867353"))
	}
}

func TestTokenSvc_InvalidateAfterRevocation(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	tokenSvc := NewTestTokenSvc(db)

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

	err = tokenSvc.Revoke(ctx, token.Id, time.Second)
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
}

func TestTokenSvc_InvalidateAfterExpiry(t *testing.T) {
	db, err := test.NewRedisDB()
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	entropy := ulid.Monotonic(random, 0)

	tokenSvc := NewService(
		WithDB(db),
		WithEntropy(entropy),
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
	tokenSvc := NewTestTokenSvc(db)

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
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	entropy := ulid.Monotonic(random, 0)

	tokenSvc := NewService(
		WithDB(db),
		WithEntropy(entropy),
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
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	entropy := ulid.Monotonic(random, 0)

	tokenSvc := NewService(
		WithDB(db),
		WithEntropy(entropy),
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

	_, err = tokenSvc.Validate(ctx, jwtToken, "bad-client-id")
	domainErr := auth.DomainError(err)
	if domainErr == nil {
		t.Fatal("expected domain error")
	}

	if domainErr.Code() != auth.EInvalidToken {
		t.Errorf("incorrect error code, want %s got %s",
			auth.EInvalidToken, domainErr.Code())
	}
}
