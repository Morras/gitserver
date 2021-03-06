package gitserver

import (
	"errors"
	"time"

	"net/http"

	"golang.org/x/net/context"
)

var ErrUserNotFound = errors.New("User not found")

type UserStoreErr struct {
	Cause string
}

func (err UserStoreErr) Error() string {
	return "UserStore error caused by: " + err.Cause
}

func NewUserStoreErr(cause string) UserStoreErr {
	return UserStoreErr{
		Cause: cause,
	}
}

type Session struct {
	Value   string
	Expires time.Time
}

//Perhaps this should be an interface instead?
type User struct {
	ID    string
	Email string
	//There are some concerns here about thread safety
	Sessions []Session
}

type UserStore interface {
	UpdateUser(ctx context.Context, user *User) error
	LookupUser(ctx context.Context, id string) (*User, error)
}

func AuthorizedUser(req *http.Request) (*User, error) {

	if loginHandler.logger == nil {
		panic("You must call gitserver.Setup(...) before gitserver.AuthorizedUser(...)")
	}

	ctx := loginHandler.contextFromRequest(req)

	loginHandler.logger.Debugf(ctx, "Serving logged in")

	/* Check if user was already logged in */
	sc, err := sessionCookieFromRequest(req)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if err != ErrSessionCookieNotFound {
		user, err := loginHandler.userStore.LookupUser(ctx, sc.UserID)
		if err == ErrUserNotFound {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, NewUserStoreErr(err.Error())
		}
		if user != nil {
			for _, s := range user.Sessions {
				if s.Value == sc.SessionID && !isExpired(s) {
					return user, nil
				}
			}
		}
	}
	return nil, ErrUserNotFound
}
