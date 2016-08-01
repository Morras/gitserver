package gitserver_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"github.com/morras/gitserver"
	"github.com/morras/gitserver/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"encoding/base64"
)

var userStoreMock mocks.UserStore

var _ = BeforeSuite(func() {
	config := gitserver.Config{
		FilePathToFrontend: "/",
		UrlPathToApiRoot:   "/api",
		UrlPathToLogin:     "/login",
		UrlPathToLogout:    "/logout",
	}
	gitserver.Setup(mocks.ApiHandlerMock{}, config, &userStoreMock, mocks.ContextProviderMock{}, &mocks.LoggerMock{})
})

var _ = Describe("AuthorizedUser", func() {

	Context("When request does not have a session cookie", func() {
		It("Should return ErrUserNotFound and no user", func() {
			req := createDummyRequest()
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When the session is expired in the userstore", func() {
		It("Should return ErrUserNotFOund and no user", func() {

			sessionID := "Seeions ID for expired test"

			userStoreMock.LookupUserCall.Returns.Err = nil
			userStoreMock.Store.Users = []gitserver.User{
				{
					ID:    "42",
					Email: "test@tests.tildeslash.dk",
					Sessions: []gitserver.Session{
						createUserStoreSession(sessionID, -1),
					},
				},
			}

			req := createRequestWithCookie("42", sessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When two users have a cookie with the same sessionID but only one has it in the userstore", func() {

		var (
			validUserID     = "valid user"
			invalidUserID   = "invalid user"
			commonSessionID = "common session id"
		)

		BeforeEach(func() {
			userStoreMock.LookupUserCall.Returns.Err = nil
			userStoreMock.Store.Users = []gitserver.User{
				{
					ID:    validUserID,
					Email: "test1@tests.tildeslash.dk",
					Sessions: []gitserver.Session{
						createUserStoreSession(commonSessionID, 1),
					},
				},
				{
					ID:    invalidUserID,
					Email: "test1@tests.tildeslash.dk",
					Sessions: []gitserver.Session{
						createUserStoreSession(commonSessionID + "invalidation suffix", 1),
					},
				},
			}
		})

		It("Should return the user if the userID matches and no errors", func() {
			req := createRequestWithCookie(validUserID, commonSessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).ShouldNot(BeNil())
			Expect(user.ID).Should(BeIdenticalTo(validUserID))
			Expect(err).Should(BeNil())
		})

		It("Should not return ErrUserNotFound and no user if the userID does not match", func() {
			req := createRequestWithCookie(invalidUserID, commonSessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})
})

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
