// Package loginhistoryapi provides an HTTP API for login history.
package loginhistoryapi

import (
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

type service struct {
	logger   log.Logger
	repoMngr auth.RepositoryManager
}

// List returns a paginated list of LoginHistory records.
func (s *service) List(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	// TODO Update token service to create LoginHistory records (refactor signup/login)
	// TODO Update token service to refresh the history record
	pr, err := decodePaginatedRequest(r)
	if err != nil {
		return nil, err
	}

	history, err := s.repoMngr.LoginHistory().ByUserID(ctx, userID, pr.Limit, pr.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup login history: %w", err)
	}

	response := &listResponse{}
	response.Create(history)

	return response, nil
}
