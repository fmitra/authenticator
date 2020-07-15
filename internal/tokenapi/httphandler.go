package tokenapi

import (
	"net/http"

	"github.com/didip/tollbooth/v6"
	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.TokenAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "Token.Verify", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/token/verify", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Revoke, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, tollbooth.NewLimiter(
			httpapi.ThrottleEveryOneSec, nil,
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, "Token.Revoke", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/token/{tokenID}", httpHandler).Methods("Delete")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Refresh, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RefreshTokenMiddleware(handler)
		handler = httpapi.RateLimitMiddleware(handler, tollbooth.NewLimiter(
			httpapi.ThrottleEveryFiveMin, nil,
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, "Token.Refresh", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/token/refresh", httpHandler).Methods("Post")
	}
}
