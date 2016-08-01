package mocks

import (
	"github.com/morras/gitserver"
	"golang.org/x/net/context"
)

type UserStore struct {

    Store struct {
        Users []gitserver.User
    }

	UpdateUserCall struct {
		Receives struct {
			Ctx  context.Context
			User *gitserver.User
		}
		Returns struct {
			Err error
		}
	}

	LookupUserCall struct {
		Receives struct {
			Ctx context.Context
			ID  string
		}
        Returns struct {
            Err error
        }
	}
}

func (us *UserStore) UpdateUser(ctx context.Context, user *gitserver.User) error {
	us.UpdateUserCall.Receives.Ctx = ctx
	us.UpdateUserCall.Receives.User = user

	return us.UpdateUserCall.Returns.Err
}

func (us *UserStore) LookupUser(ctx context.Context, id string) (*gitserver.User, error) {
	us.LookupUserCall.Receives.Ctx = ctx
	us.LookupUserCall.Receives.ID = id

    for _, u := range us.Store.Users {
        if u.ID == id {
            return &u, nil
        }
    }

	return nil, us.LookupUserCall.Returns.Err
}
