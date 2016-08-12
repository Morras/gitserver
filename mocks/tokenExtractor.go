package mocks

import (
	"net/http"

	"github.com/google/identity-toolkit-go-client/gitkit"
	"golang.org/x/net/context"
)

type TokenExtractor struct {
	ExtractTokenCall struct {
		Returns struct {
			Token *gitkit.Token
			Error error
		}
	}
}

//I do not care about the input
func (t *TokenExtractor) ExtractToken(req *http.Request, ctx context.Context, audience []string) (*gitkit.Token, error) {
	return t.ExtractTokenCall.Returns.Token, t.ExtractTokenCall.Returns.Error
}
