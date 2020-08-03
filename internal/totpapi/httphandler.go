package totpapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.TOTPAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.Secret, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"TOTPAPI.Secret", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/totp", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"TOTPAPI.Verify", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/totp/configure", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"TOTPAPI.Remove", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/totp/configure", httpHandler).Methods("Delete")
	}
}
