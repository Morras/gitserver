package gitserver

import (
	"fmt"
	"net/http"

	"github.com/google/identity-toolkit-go-client/gitkit"
	"golang.org/x/net/context"
)

type TokenExtractor interface {
	ExtractToken(req *http.Request, ctx context.Context, audience []string) (*gitkit.Token, error)
}

type GitTokenExtractor struct {
}

func (*GitTokenExtractor) ExtractToken(req *http.Request, ctx context.Context, audience []string) (*gitkit.Token, error) {
	config := gitkit.Config{}
	client, err := gitkit.New(ctx, &config)
	if err != nil {
		return nil, err
	}

	ts := client.TokenFromRequest(req)

	token, err := client.ValidateToken(ctx, ts, audience)

	if err != nil {
		err = fmt.Errorf("Unable to validate token %v, error %v", ts, err)
	}

	return token, err

}
