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
func SetupHTTPHandler(svc auth.ContactAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.CheckAddress, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "ContactAPI.CheckAddress", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusAccepted)
		router.HandleFunc("/api/v1/contact/check-address", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Disable, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "ContactAPI.Disable", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/disable", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "ContactAPI.Verify", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/verify", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc, auth.JWTAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "ContactAPI.Remove", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/contact/send", httpHandler).Methods("Post")
	}
}
