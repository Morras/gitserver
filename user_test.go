package gitserver_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"encoding/base64"

	"errors"
	"github.com/morras/gitserver"
	"github.com/morras/gitserver/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

	Context("When the UserStore is empty", func() {
		It("Should return ErrUserNotFound and no user", func() {

			sessionID := "Seeions ID for empty userstore sessions"

			userStoreMock.LookupUserCall.Returns.Err = gitserver.ErrUserNotFound
			userStoreMock.Store.Users = []gitserver.User{}

			req := createRequestWithCookie("42", sessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When request does not have a session cookie", func() {
		It("Should return ErrUserNotFound and no user", func() {
			req := createDummyRequest()
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When a user has multiple sessions where one is valid", func() {
		It("Should return the user if the session ID matches the valid session", func() {
			sessionID1 := "Session id 1"
			sessionID2 := "Session id 2"
			sessionID3 := "Session id 3"

			userStoreMock.LookupUserCall.Returns.Err = nil
			userStoreMock.Store.Users = []gitserver.User{
				{
					ID:    "42",
					Email: "test@test.tildeslash.dk",
					Sessions: []gitserver.Session{
						createUserStoreSession(sessionID1, -1),
						createUserStoreSession(sessionID2, 1),
						createUserStoreSession(sessionID3, -1),
					},
				},
			}

			req := createRequestWithCookie("42", sessionID2)
			user, err := gitserver.AuthorizedUser(req)

			Expect(err).NotTo(HaveOccurred())
			Expect(user.ID).Should(BeIdenticalTo("42"))
			Expect(user.Email).Should(BeIdenticalTo("test@test.tildeslash.dk"))
		})
	})

	Context("When there are no sessions in the userstore", func() {
		It("Should return ErrUserNotFound and no user", func() {

			sessionID := "Seeions ID for empty userstore sessions"

			userStoreMock.LookupUserCall.Returns.Err = nil
			userStoreMock.Store.Users = []gitserver.User{
				{
					ID:       "42",
					Email:    "test@tests.tildeslash.dk",
					Sessions: []gitserver.Session{},
				},
			}

			req := createRequestWithCookie("42", sessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When the session is expired in the userstore", func() {
		It("Should return ErrUserNotFound and no user", func() {

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
						createUserStoreSession(commonSessionID+"invalidation suffix", 1),
					},
				},
			}
		})

		It("Should call the UserStore with the UserID of the cookie", func() {
			req := createRequestWithCookie(validUserID, commonSessionID)
			gitserver.AuthorizedUser(req)
			Expect(userStoreMock.LookupUserCall.Receives.ID).To(BeIdenticalTo(validUserID))
		})

		It("Should return the user if the userID matches and no errors", func() {
			req := createRequestWithCookie(validUserID, commonSessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).ShouldNot(BeNil())
			Expect(user.ID).Should(BeIdenticalTo(validUserID))
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should return ErrUserNotFound and no user if the userID does not match", func() {
			req := createRequestWithCookie(invalidUserID, commonSessionID)
			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When the cookie value is not a valid BASE64 encoded value", func() {
		It("Should return ErrUserNotFound and no user", func() {
			req := createDummyRequest()
			c := http.Cookie{
				Name:   gitserver.CookieName,
				Value:  "Not a base 64 encoded value",
				MaxAge: 1 * 60 * 60,
			}
			req.AddCookie(&c)

			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When the cookie value is not a valid SessionCookie", func() {
		It("Should return ErrUserNotFound and no user", func() {
			req := createDummyRequest()
			value := []byte("Nonsence value")
			encodedValue := base64.StdEncoding.EncodeToString(value)
			c := http.Cookie{
				Name:   gitserver.CookieName,
				Value:  encodedValue,
				MaxAge: 1 * 60 * 60,
			}
			req.AddCookie(&c)

			user, err := gitserver.AuthorizedUser(req)

			Expect(user).Should(BeNil())
			Expect(err).Should(BeIdenticalTo(gitserver.ErrUserNotFound))
		})
	})

	Context("When the UserStore gives an error", func() {
		It("Should return a UserStoreErr with details, and no user", func() {
			causeText := "Mocked cause of the error"
			userStoreError := errors.New(causeText)
			userStoreMock.LookupUserCall.Returns.Err = userStoreError
			req := createRequestWithCookie("User id for UserStore error", "Session id for UserStore error")
			user, err := gitserver.AuthorizedUser(req)
			Expect(user).Should(BeNil())
			Expect(err).Should(BeAssignableToTypeOf(gitserver.NewUserStoreErr("reference")))
			Expect(err).To(BeIdenticalTo(gitserver.NewUserStoreErr(causeText)))
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
