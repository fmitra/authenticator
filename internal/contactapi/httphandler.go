package contactapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.ContactAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.CheckAddress, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"ContactAPI.CheckAddress", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusAccepted)
		router.HandleFunc("/api/v1/contact/check-address", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Disable, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"ContactAPI.Disable", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/disable", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"ContactAPI.Verify", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/verify", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"ContactAPI.Remove", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/remove", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Send, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"ContactAPI.Send", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusAccepted)
		router.HandleFunc("/api/v1/contact/send", httpHandler).Methods("Post")
	}
}
