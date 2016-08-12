package mocks

import (
	"golang.org/x/net/context"
	"net/http"
)

//Stupid minimal mock needed to fulfill a contract
type ContextProviderMock struct {
}

func (c ContextProviderMock) ContextFromRequest(req *http.Request) context.Context {
	return nil
}
