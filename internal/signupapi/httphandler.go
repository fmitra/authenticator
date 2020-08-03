package signupapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods
// to http handlers.
func SetupHTTPHandler(svc auth.SignUpAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = svc.SignUp
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"SignUpAPI.SignUp", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/signup", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"SignUpAPI.Verify", httpapi.PerMinute, int64(10),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/signup/verify", httpHandler).Methods("Post")
	}
}
