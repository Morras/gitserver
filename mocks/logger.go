package mocks

import (
	"golang.org/x/net/context"
)

//Stupid minimal mock needed to fulfill a contract
type LoggerMock struct {
}

func (*LoggerMock) Debugf(ctx context.Context, format string, v ...interface{}) {
}

func (*LoggerMock) Infof(ctx context.Context, format string, v ...interface{}) {
}

func (*LoggerMock) Errorf(ctx context.Context, format string, v ...interface{}) {
}
