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
func SetupHTTPHandler(svc auth.TOTPAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.Secret, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "TOTPAPI.Secret", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/totp", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "TOTPAPI.Verify", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/totp/configure", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "TOTPAPI.Remove", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/totp/configure", httpHandler).Methods("Delete")
	}
}
