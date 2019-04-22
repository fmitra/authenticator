// Package httpapi provides common encoding and middleware for an HTTP API.
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// JSONAPIHandler is an HTTP handler for a JSON API.
type JSONAPIHandler func(w http.ResponseWriter, r *http.Request) (interface{}, error)

// ToHandlerFunc adapts a JSONAPIHandler into net/http's HandlerFunc.
func ToHandlerFunc(jsonHandler JSONAPIHandler, successCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response, err := jsonHandler(w, r)
		if err != nil {
			ErrorResponse(w, err)
			return
		}

		JSONResponse(w, response, successCode)
	}
}

// GetUserID retrieves a User ID from context.
func GetUserID(r *http.Request) (string, error) {
	ctx := r.Context()
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return "", errors.New("no user ID available")
	}
	return userID, nil
}

// JSONResponse writes a response body. If a struct is provided
// and we are unable to marshal it, we return an internal error.
func JSONResponse(w http.ResponseWriter, v interface{}, statusCode int) {
	if v == nil {
		response(w, []byte(""), statusCode)
	}

	b, ok := v.([]byte)
	if ok {
		response(w, b, statusCode)
		return
	}

	b, err := json.Marshal(v)
	if err != nil {
		internalErrorResponse(w)
		return
	}

	response(w, b, statusCode)
}

// ErrorResponse writes an error response. Domain errors
// are returned to the client. Any other errors, will resolve
// to 500 error response.
func ErrorResponse(w http.ResponseWriter, err error) {
	domainErr := auth.DomainError(err)
	if domainErr == nil {
		internalErrorResponse(w)
		return
	}

	var statusCode int
	switch domainErr.Code() {
	case auth.EInvalidToken:
		statusCode = http.StatusUnauthorized
	default:
		statusCode = http.StatusBadRequest
	}

	content := errorMessage(string(domainErr.Code()), domainErr.Message())
	response(w, content, statusCode)
}

func errorMessage(code, message string) []byte {
	responseStr := `{
		"error": {
			"code": "%s",
			"message": "%s"
		}
	}`
	return []byte(fmt.Sprintf(responseStr, code, message))
}

func response(w http.ResponseWriter, content []byte, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(content)
}

func internalErrorResponse(w http.ResponseWriter) {
	code := "internal"
	message := "An internal error occurred"
	content := errorMessage(code, message)
	response(w, content, http.StatusInternalServerError)
}
