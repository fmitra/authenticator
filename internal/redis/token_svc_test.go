package redis

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"github.com/oklog/ulid"

	auth "github.com/fmitra/authenticator"
)

func TestTokenSvc_Create(t *testing.T) {
	db, err := NewTestRedisDB("0")
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	tokenSvc := NewTestTokenSvc(db)

	token, clientID, err := tokenSvc.Create(ctx, user)
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

	if clientID == "" {
		t.Error("invalid clientID generated for token")
	}

	h := sha512.New()
	h.Write([]byte(clientID))
	clientIDHash := hex.EncodeToString(h.Sum(nil))

	if clientIDHash != token.ClientID {
		t.Errorf("client ID does not match: want %s got %s",
			clientIDHash, token.ClientID)
	}
}

func TestTokenSvc_InvalidateAfterRevocation(t *testing.T) {
	db, err := NewTestRedisDB("1")
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer db.Close()

	ctx := context.Background()
	user := &auth.User{ID: "user_id"}
	tokenSvc := NewTestTokenSvc(db)

	token, _, err := tokenSvc.Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken)
	if err != nil {
		t.Error("failed to validate token:", err)
	}

	err = tokenSvc.Revoke(ctx, token.Id, time.Second)
	if err != nil {
		t.Error("failed to revoke token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken)
	if err == nil {
		t.Fatal("revoked token should return error")
	}
	if auth.ErrorCode(err) != auth.ErrTokenInvalid {
		t.Errorf("incorrect error: want %s got %s",
			auth.ErrTokenInvalid, err)
	}
}

func TestTokenSvc_InvalidateAfterExpiry(t *testing.T) {
	db, err := NewTestRedisDB("2")
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
	)

	token, _, err := tokenSvc.Create(ctx, user)
	if err != nil {
		t.Fatal("failed to create token:", err)
	}

	jwtToken, err := tokenSvc.Sign(ctx, token)
	if err != nil {
		t.Fatal("failed to sign token:", err)
	}

	_, err = tokenSvc.Validate(ctx, jwtToken)
	if err != nil {
		t.Error("failed to validate token:", err)
	}

	time.Sleep(time.Second)
	_, err = tokenSvc.Validate(ctx, jwtToken)
	if err == nil {
		t.Error("expired token should return error")
	}
}
