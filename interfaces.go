package gitserver

import (
    "golang.org/x/net/context"
    "time"
    "net/http"
)

type Session struct {
    Value string
    Expires time.Time 
}

type User struct {
    ID string
    Email string
    //There are some concerns here about thread safety
    Sessions []Session
}

type UserStore interface {
    //TODO might not be needed LookupUser() *User
    //This should not alter the sessions, there are some concerns about thread safety
    UpdateUser(ctx context.Context, user *User) (*User, error)
    LookupUser(ctx context.Context, id string) (*User, error)
    Sessions(ctx context.Context, id string) []Session
}

type ContextProvider interface {
    ContextFromRequest(req *http.Request) context.Context
}