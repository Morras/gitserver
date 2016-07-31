package gitserver

import (
	"encoding/json"
	"net/http"
	"testing"
	"github.com/morras/gitserver/mocks"
)

func TestNoCookie(t *testing.T) {
    setup();
	req := http.Request{}
	user, err := AuthorizedUser(&req)

	if err != ErrUserNotFound {
		t.Errorf("Expected error: %v, and user: %v, got error: %v, and user: %v", ErrUserNotFound, nil, user, err)
	}
}

func setupRequestWithCookie(userID string, sessionID string, t *testing.T) http.Request {

	//Create and set cookie
	sc := sessionCookie{
		UserID:    userID,
		SessionID: sessionID,
	}

	cookieValue, err := json.Marshal(sc)
	if err != nil {
		t.Errorf("Unable to marshal cookie: %v, %v", sc, err)
	}

	c := http.Cookie{
		Name:   cookieName,
		Value:  string(cookieValue),
		MaxAge: 1 * 60 * 60, //1 hour, this value is only important for the browser and has not meaning in the tests.
	}

	req := http.Request{}
	req.AddCookie(&c)

	return req
}

func setup() {

    config := Config{
        FilePathToFrontend: "/",
        UrlPathToApiRoot: "/api",
        UrlPathToLogin: "/login",
        UrlPathToLogout: "/logout",
    }
	Setup(mocks.ApiHandlerMock{}, config, nil, mocks.ContextProviderMock{}, &mocks.LoggerMock{})
}



