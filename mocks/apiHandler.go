package mocks

import (
	"net/http"
)

type ApiHandlerMock struct {
	ServeHTTPCall struct {
		Receives struct {
			Res http.ResponseWriter
			Req *http.Request
		}
	}
}

func (api ApiHandlerMock) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	api.ServeHTTPCall.Receives.Res = res
	api.ServeHTTPCall.Receives.Req = req
}
