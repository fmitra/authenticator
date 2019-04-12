package redis

import (
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/go-kit/kit/log"
	redislib "github.com/go-redis/redis"
	"github.com/oklog/ulid"

	auth "github.com/fmitra/authenticator"
)

// NewTestRedisDB returns a redis DB for testing.
func NewTestRedisDB(dbNo string) (Rediser, error) {
	redisURL := fmt.Sprintf("redis://:swordfish@localhost:6379/%s", dbNo)

	redisConfig, err := redislib.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	db := redislib.NewClient(redisConfig)
	_, err = db.Ping().Result()
	if err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
}

// NewTestTokenSvc returns a test auth.TokenService
// with simple test configuration.
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
	)

	return tokenSvc
}
