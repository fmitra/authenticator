package deviceapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.DeviceAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.Create, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"DeviceAPI.Create", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"DeviceAPI.Verify", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/device/verify", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"DeviceAPI.Remove", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device/{deviceID}", httpHandler).Methods("Delete")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Rename, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"DeviceAPI.Rename", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device/{deviceID}", httpHandler).Methods("Patch")
	}
	{
		handler = httpapi.AuthMiddleware(svc.List, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"DeviceAPI.List", httpapi.PerMinute, int64(60),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device", httpHandler).Methods("Get")
	}
}
