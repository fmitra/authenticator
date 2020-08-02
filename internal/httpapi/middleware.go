package httpapi

import (
	"context"
	"net/http"

	"github.com/didip/tollbooth/v6"
	"github.com/didip/tollbooth/v6/limiter"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/token"
)

type contextKey string

const authorizationHeader = "AUTHORIZATION"
const userIDContextKey contextKey = "userID"
const tokenContextKey contextKey = "token"
const refreshTokenContextKey contextKey = "refreshToken"

// ThrottleEveryOneSec limits a user requests to roughly every second.
const ThrottleEveryOneSec = float64(1)

// ThrottleEveryTenSec limits a user requests to roughly every ten seconds.
const ThrottleEveryTenSec = float64(.1)

// ThrottleEveryFiveMin limits a user requests to roughly every five minutes.
const ThrottleEveryFiveMin = float64(.003)

// RateLimitMiddleware is an adapter to use tollbooth's ratelimiting library
// with our HTTP middleware.
func RateLimitMiddleware(jsonHandler JSONAPIHandler, lmt *limiter.Limiter) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		httpErr := tollbooth.LimitByRequest(lmt, w, r)
		if httpErr != nil {
			lmt.ExecOnLimitReached(w, r)
			return nil, auth.ErrThrottle("requests are throttled, try again later")
		}

		return jsonHandler(w, r)
	}
}

// AuthMiddleware validates an Authorization header if available.
func AuthMiddleware(jsonHandler JSONAPIHandler, tokenSvc auth.TokenService, state auth.TokenState) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		ctx := r.Context()
		jwtToken := r.Header.Get(authorizationHeader)
		if jwtToken == "" {
			return nil, auth.ErrInvalidToken("user is not authenticated")
		}

		clientIDCookie, err := r.Cookie(token.ClientIDCookie)
		if err != nil {
			return nil, auth.ErrInvalidToken("token source is invalid")
		}

		token, err := tokenSvc.Validate(ctx, jwtToken, clientIDCookie.Value)
		if err != nil {
			return nil, err
		}

		if token.State != state {
			return nil, auth.ErrInvalidToken("token state is not supported")
		}

		var newCtx context.Context
		{
			newCtx = context.WithValue(ctx, userIDContextKey, token.UserID)
			newCtx = context.WithValue(newCtx, tokenContextKey, token)
		}

		r = r.WithContext(newCtx)

		return jsonHandler(w, r)
	}
}

// RefreshTokenMiddleware sets a refresh token in context.
func RefreshTokenMiddleware(jsonHandler JSONAPIHandler) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		ctx := r.Context()

		refreshToken, err := r.Cookie(token.RefreshTokenCookie)
		if err == nil {
			newCtx := context.WithValue(ctx, refreshTokenContextKey, refreshToken.Value)
			r = r.WithContext(newCtx)
		}

		return jsonHandler(w, r)
	}
}

// ErrorLoggingMiddleware logs any errors that are returned before
// being parsed to an HTTP response.
func ErrorLoggingMiddleware(jsonHandler JSONAPIHandler, source string, log log.Logger) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		userID := GetUserID(r)
		response, err := jsonHandler(w, r)
		if err != nil {
			level.Info(log).Log(
				"user_id", userID,
				"source", source,
				"error", err,
			)
		}
		return response, err
	}
}
