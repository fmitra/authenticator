package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"

	auth "github.com/fmitra/authenticator"
)

// Rate is the rate of allowed requests. We support
// r/min and r/second.
type Rate string

const (
	// PerSecond allows us to accept x requests per second
	PerSecond Rate = "per_second"
	// PerMinute allows us to accept x requests per minute
	PerMinute = "per_minute"
)

// HHMMSS formats a timestamp as HH:MM:SS
// Reference: https://yourbasic.org/golang/format-parse-string-time-date-example/
const HHMMSS = "15:04:05"

// HHMM formats a timestamp as HH:MM
// Reference: https://yourbasic.org/golang/format-parse-string-time-date-example/
const HHMM = "15:04"

type rediser interface {
	TxPipelined(ctx context.Context, fn func(pipe redis.Pipeliner) error) ([]redis.Cmder, error)
}

// Limiter provides rate limiting tooling
type Limiter interface {
	// RateLimit applies basic rate limiting to an HTTP request.
	RateLimit(r *http.Request) error
}

// LimiterFactory creates new Limiters
type LimiterFactory interface {
	// NewLimiter returns a new Limiter.
	NewLimiter(prefix string, rate Rate, max int64) Limiter
}

type factory struct {
	rdb rediser
}

type ratelimiter struct {
	rdb    rediser
	rate   Rate
	max    int64
	prefix string
}

// NewLimiter creates a new Limiter.
func (f *factory) NewLimiter(prefix string, rate Rate, max int64) Limiter {
	return &ratelimiter{
		rdb:    f.rdb,
		prefix: prefix,
		rate:   rate,
		max:    max,
	}
}

// RateLimit applies basic rate limiting to an HTTP request as described
// in Redis' onboarding documentation.
// Reference: https://redislabs.com/redis-best-practices/basic-rate-limiting/
func (l *ratelimiter) RateLimit(r *http.Request) error {
	var now string
	var expiry time.Duration
	var id string

	if l.rate == PerSecond {
		now = time.Now().Format(HHMMSS)
		expiry = time.Second
	} else {
		now = time.Now().Format(HHMM)
		expiry = time.Minute
	}

	id = GetUserID(r)
	if id == "" {
		id = GetIP(r)
	}

	ctx := r.Context()
	key := fmt.Sprintf("%s:%s:%s", l.prefix, id, now)
	key = base64.RawURLEncoding.EncodeToString([]byte(key))

	var incr *redis.IntCmd
	_, err := l.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		incr = pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, expiry)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to increment counter: %w", err)
	}

	if incr.Val() > l.max {
		return auth.ErrThrottle("requests are throttled, try again later")
	}

	return nil
}

// NewRateLimiter returns a new Limiter.
func NewRateLimiter(db rediser) LimiterFactory {
	return &factory{rdb: db}
}
