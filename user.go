package gitserver

import (
	"errors"
	"time"

	"golang.org/x/net/context"
)

var ErrUserNotFound = errors.New("Session cookie not found")

type Session struct {
	Value   string
	Expires time.Time
}

type User struct {
	ID    string
	Email string
	//There are some concerns here about thread safety
	Sessions []Session
}

type UserStore interface {
	//TODO might not be needing Sessions
	UpdateUser(ctx context.Context, user *User) (*User, error)
	LookupUser(ctx context.Context, id string) (*User, error)
	Sessions(ctx context.Context, id string) []Session
}
