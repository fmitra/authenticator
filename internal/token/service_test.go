package token

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
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

	if token.ClientID == "" {
		t.Error("invalid clientID generated for token")
	}

	if token.Code != "" || token.CodeHash != "" {
		t.Error("otp codes should not be generated for authorized tokens")
	}

	h := sha512.New()
	h.Write([]byte(token.ClientID))
	clientIDHash := hex.EncodeToString(h.Sum(nil))

	if clientIDHash != token.ClientIDHash {
		t.Errorf("client ID does not match: want %s got %s",
			clientIDHash, token.ClientID)
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

	_, err = tokenSvc.Create(ctx, user, auth.JWTPreAuthorized)
	if err != nil {
		t.Fatal("failed to create token:", err)
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

	token, err := tokenSvc.CreateWithOTP(ctx, user, auth.JWTPreAuthorized, auth.Phone)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	if token.Code == "" || token.CodeHash == "" {
		t.Fatal("otp codes should be generated for pre-authorized tokens")
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
	}
	tokenSvc := NewTestTokenSvc(db)

	token, err := tokenSvc.CreateWithOTPAndAddress(ctx, user, auth.JWTPreAuthorized, auth.Phone, "jane@example.com")
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	if token.Code == "" || token.CodeHash == "" {
		t.Fatal("otp codes should be generated for pre-authorized tokens")
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
