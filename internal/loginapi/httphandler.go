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
func SetupHTTPHandler(svc auth.LoginAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = svc.Login
		handler = httpapi.ErrorLoggingMiddleware(handler, "LoginAPI.Login", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.VerifyDevice, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "LoginAPI.VerifyDevice", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login/verify-device", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.VerifyCode, tokenSvc, auth.JWTPreAuthorized)
		handler = httpapi.ErrorLoggingMiddleware(handler, "LoginAPI.VerifyCode", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/login/verify-code", httpHandler).Methods("Post")
	}
}
