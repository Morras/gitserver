package gitserver_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/morras/gitserver"
	"github.com/morras/gitserver/mocks"
)

func TestGitserver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gitserver Suite")
}

var userStoreMock mocks.UserStore
var config = gitserver.Config{
	FilePathToFrontend: "/",
	URLPathToApiRoot:   "/api",
	URLPathToLogin:     "/login",
	URLPathToLogout:    "/logout",
	LoginRedirectURL:   "/LoginRedirectURL",
	LogoutRedirectURL:  "/LogoutRedirectURL",
	NewUserRedirectURL: "/NewUserRedirectURL",
	SessionDuration:    42,
}

// There are some problems where we can only call Setup once because it
// tries to setup handlers for the same endpoint otherwise which gives a panic.
// We need Setup run to be able to test AuthorizedUser as it requires the global
// Login to be set so it can use some of its methods.
// I do not like injecting Login into AuthorizedUser as users of the server should
// not have to bother with instantializing the Login as that is done by calling Setup
var _ = BeforeSuite(func() {
	gitserver.Setup(mocks.ApiHandlerMock{}, config, &userStoreMock, mocks.ContextProviderMock{}, &mocks.LoggerMock{})
})

// Common helper methods

func createUserStoreSession(value string, expiresInHours int64) gitserver.Session {
	return gitserver.Session{
		Value:   value,
		Expires: time.Now().Add(time.Duration(expiresInHours) * time.Hour),
	}
}

func createRequestWithCookie(userID string, sessionID string) *http.Request {

	//Create and set cookie
	sc := gitserver.SessionCookie{
		UserID:    userID,
		SessionID: sessionID,
	}

	cookieValue, err := json.Marshal(sc)
	if err != nil {
		Fail(fmt.Sprintf("Unable to marshal cookie: %v, %v", sc, err))
	}
	encodedCookieValue := base64.StdEncoding.EncodeToString(cookieValue)

	c := http.Cookie{
		Name:   gitserver.CookieName,
		Value:  encodedCookieValue,
		MaxAge: 1 * 60 * 60, //1 hour, this value is only important for the browser and has not meaning in the tests.
	}

	req := createDummyRequest()
	req.AddCookie(&c)

	return req
}

func createDummyRequest() *http.Request {
	req, err := http.NewRequest("Get", "/", nil)
	if err != nil {
		Fail(fmt.Sprintf("Unable to create dummy request %v", err))
	}

	return req
}
