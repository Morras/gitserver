package gitserver

import (
	"net/http"

	"golang.org/x/net/context"
)

type ContextProvider interface {
	ContextFromRequest(req *http.Request) context.Context
}
