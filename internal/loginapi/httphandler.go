package loginapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.LoginAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = svc.Login
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"LoginAPI.Login", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.DeviceChallenge, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"LoginAPI.DeviceChallenge", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login/verify-device", httpHandler).Methods("Get")
	}
	{
		handler = httpapi.AuthMiddleware(svc.VerifyDevice, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"LoginAPI.VerifyDevice", httpapi.PerMinute, int64(20),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login/verify-device", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.VerifyCode, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"LoginAPI.VerifyCode", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login/verify-code", httpHandler).Methods("Post")
	}
}
