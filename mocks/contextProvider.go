package mocks

import (
	"net/http"
	"golang.org/x/net/context"
)

//Stupid minimal mock needed to fulfill a contract
type ContextProviderMock struct {
}

func (c ContextProviderMock) ContextFromRequest(req *http.Request) context.Context {
	return nil
}