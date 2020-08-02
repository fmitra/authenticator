package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/google/go-cmp/cmp"

	"github.com/gorilla/mux"
)

// ServerResp is a path and response for an external test server.
type ServerResp struct {
	Path       string
	Resp       string
	StatusCode int
}

// Server creates an external test server with mocked responses.
func Server(resps ...ServerResp) *httptest.Server {
	router := mux.NewRouter()
	for i := range resps {
		sr := resps[i]
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			undefinedStatus := 0
			if sr.StatusCode != undefinedStatus {
				w.WriteHeader(sr.StatusCode)
			}

			fmt.Fprintln(w, sr.Resp)
		})

		router.HandleFunc(sr.Path, handler)
	}

	s := httptest.NewServer(router)
	return s
}

// ValidateErrMessage validates an API error message in the format
// of { error: { message: "", code: "" } }
func ValidateErrMessage(expectedMsg string, body *bytes.Buffer) error {
	if expectedMsg == "" {
		return nil
	}

	var errResponse map[string]map[string]string
	err := json.NewDecoder(body).Decode(&errResponse)
	if err != nil {
		return err
	}

	if errResponse["error"]["message"] != expectedMsg {
		return fmt.Errorf(cmp.Diff(expectedMsg, errResponse["error"]["message"]))
	}

	return nil
}

// SetAuthHeaders sets authentication header and client ID cookie
// to the client request for API testing.
func SetAuthHeaders(r *http.Request) {
	cookie := http.Cookie{
		Name:     "CLIENTID",
		Value:    "client-id",
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		Raw:      "client-id",
	}
	r.Header.Set("AUTHORIZATION", "JWTTOKEN")
	r.AddCookie(&cookie)
}
