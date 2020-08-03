package httpapi

import (
	"net/http"
)

// MockLimiterFactory is a stub for LimiterFactory interface.
type MockLimiterFactory struct{}

// MockLimiter is a stub for Limiter interface.
type MockLimiter struct{}

// RateLimit mock.
func (m *MockLimiter) RateLimit(r *http.Request) error {
	return nil
}

// NewLimiter mock.
func (m *MockLimiterFactory) NewLimiter(pefix string, rate Rate, max int64) Limiter {
	return &MockLimiter{}
}
