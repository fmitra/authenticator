package signupapi

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
func SetupHTTPHandler(svc auth.SignUpAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = svc.SignUp
		handler = httpapi.RateLimitMiddleware(handler, tollbooth.NewLimiter(
			httpapi.ThrottleEveryOneSec, nil,
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, "SignUpAPI.SignUp", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/signup", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, tollbooth.NewLimiter(
			httpapi.ThrottleEveryOneSec, nil,
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, "SignUpAPI.Verify", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/signup/verify", httpHandler).Methods("Post")
	}
}
