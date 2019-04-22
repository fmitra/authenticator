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
func SetupHTTPHandler(svc auth.DeviceAPI, router *mux.Router, tokenSvc auth.TokenService, logger log.Logger) {
	var handler httpapi.JSONAPIHandler
	{
		handler = httpapi.AuthMiddleware(svc.Create, tokenSvc)
		handler = httpapi.ErrorLoggingMiddleware(handler, "DeviceAPI.Create", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Verify, tokenSvc)
		handler = httpapi.ErrorLoggingMiddleware(handler, "DeviceAPI.Verify", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusCreated)
		router.HandleFunc("/api/v1/device/verify", httpHandler).Methods("Post")
	}
	{
		handler = httpapi.AuthMiddleware(svc.Remove, tokenSvc)
		handler = httpapi.ErrorLoggingMiddleware(handler, "DeviceAPI.Remove", logger)
		httpHandler := httpapi.ToHandlerFunc(handler, http.StatusOK)
		router.HandleFunc("/api/v1/device/{deviceID}", httpHandler).Methods("Delete")
	}
}
