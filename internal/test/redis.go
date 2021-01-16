package test

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/go-redis/redis/v8"
)

// NewRedisDB returns a redis DB for testing.
// We allocate a random DB to avoid race conditions
// in teardown/setup methods.
func NewRedisDB() (*redis.Client, error) {
	rand.Seed(time.Now().UnixNano())
	// nolint:gosec // crypto/rand not applicable for test package
	dbNo := rand.Intn(16)
	redisURL := fmt.Sprintf("redis://:swordfish@localhost:6379/%v", dbNo)

	redisConfig, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	db := redis.NewClient(redisConfig)
	_, err = db.Ping(ctx).Result()
	if err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
}
