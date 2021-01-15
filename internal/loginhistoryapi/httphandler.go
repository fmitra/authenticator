package loginhistoryapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

// SetupHTTPHandler converts a service's public methods to
// http handlers.
func SetupHTTPHandler(svc auth.LoginHistoryAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger, lmt httpapi.LimiterFactory) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.List, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.RateLimitMiddleware(handler, lmt.NewLimiter(
			"LoginHistoryAPI.List", httpapi.PerMinute, int64(45),
		))
		handler = httpapi.ErrorLoggingMiddleware(handler, logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login-history", httpHandler).Methods("Get")
	}
}
