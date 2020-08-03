package httpapi

import (
	"context"
	"net/http"

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

// RateLimitMiddleware rate limits HTTP requests.
func RateLimitMiddleware(jsonHandler JSONAPIHandler, lmt Limiter) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		err := lmt.RateLimit(r)
		if err != nil {
			return nil, err
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
func ErrorLoggingMiddleware(jsonHandler JSONAPIHandler, log log.Logger) JSONAPIHandler {
	return func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
		userID := GetUserID(r)
		response, err := jsonHandler(w, r)
		if err != nil {
			level.Info(log).Log(
				"path", r.URL.Path,
				"method", r.Method,
				"user_id", userID,
				"error", err,
			)
		}
		return response, err
	}
}
