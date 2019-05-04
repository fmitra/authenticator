package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/pkg/errors"

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
		return errors.Errorf("incorrect error resposne, want '%s' got '%s'",
			expectedMsg, errResponse["error"]["message"])
	}

	return nil
}
