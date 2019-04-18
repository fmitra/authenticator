package signupapi

import (
	"testing"

	"github.com/go-kit/kit/log"

	"github.com/fmitra/authenticator/internal/pg"
	"github.com/fmitra/authenticator/internal/redis"
)

func TestSignUpAPI_SignUp(t *testing.T) {
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

	t.Error("not implemented", svc)
}

func TestSignUpAPI_Verify(t *testing.T) {
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

	t.Error("not implemented", svc)
}
