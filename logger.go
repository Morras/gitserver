package gitserver

import (
	"golang.org/x/net/context"
)

type ContextAwareLogger interface {
	//Debug(ctx context.Context, message string)
	Debugf(ctx context.Context, format string, v ...interface{})

	//Info(ctx context.Context, message string)
	Infof(ctx context.Context, format string, v ...interface{})

	//Error(ctx context.Context, message string)
	Errorf(ctx context.Context, format string, v ...interface{})
}
