package signupapi

import (
	"testing"

	"github.com/go-kit/kit/log"

	"github.com/fmitra/authenticator/internal/test"
)

func TestSignUpAPI_SignUp(t *testing.T) {
	repoMngr := &test.RepositoryManager{}
	tokenSvc := &test.TokenService{}

	svc := NewService(
		WithLogger(log.NewNopLogger()),
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
	)

	t.Error("not implemented", svc)
}

func TestSignUpAPI_Verify(t *testing.T) {
	repoMngr := &test.RepositoryManager{}
	tokenSvc := &test.TokenService{}

	svc := NewService(
		WithLogger(log.NewNopLogger()),
		WithTokenService(tokenSvc),
		WithRepoManager(repoMngr),
	)

	t.Error("not implemented", svc)
}
