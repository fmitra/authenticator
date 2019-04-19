package test

import (
	"fmt"
	"strconv"

	"github.com/go-redis/redis"
)

// RedisDB is a redis DB number. We allocate
// a separate DB for each package test to avoid
// race conditions with teardown methods.
type RedisDB int

const (
	RedisTokenSvc RedisDB = iota
	RedisWebAuthn
)

// NewRedisDB returns a redis DB for testing.
func NewRedisDB(dbNo RedisDB) (*redis.Client, error) {
	redisURL := fmt.Sprintf("redis://:swordfish@localhost:6379/%s", strconv.Itoa(int(dbNo)))

	redisConfig, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	db := redis.NewClient(redisConfig)
	_, err = db.Ping().Result()
	if err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
}
