package signupapi

import (
	"context"
	"testing"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/redis"
)

func TestSignUpSvc_BeginSignUp(t *testing.T) {
	redisDB, err := redis.NewTestRedisDB("1")
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer redisDB.Close()

	repo, err := pg.NewTestClient("signupsvc_begin_signup_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pg.DropTestDB(repo, "signupsvc_begin_signup_test")

	svc := NewService(
		WithLogger(log.NewNopLogger()),
		WithTokenService(redis.NewTestTokenSvc(redisDB)),
		WithRepoManager(repo),
	)

	ctx := context.Background()
	user := &auth.User{}
	err = svc.BeginSignUp(ctx, user)
	if err != nil {
		t.Error("failed to start signup:", err)
	}
}

func TestSignUpSvc_FinishSignUp(t *testing.T) {
	redisDB, err := redis.NewTestRedisDB("1")
	if err != nil {
		t.Fatal("faliled to create test database:", err)
	}
	defer redisDB.Close()

	repo, err := pg.NewTestClient("signupsvc_begin_signup_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer pg.DropTestDB(repo, "signupsvc_begin_signup_test")

	svc := NewService(
		WithLogger(log.NewNopLogger()),
		WithTokenService(redis.NewTestTokenSvc(redisDB)),
		WithRepoManager(repo),
	)

	ctx := context.Background()
	credential := auth.Credential("credential")
	err = svc.FinishSignUp(ctx, credential)
	if err != nil {
		t.Error("failed to finish signup:", err)
	}
}
