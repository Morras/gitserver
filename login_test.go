package gitserver_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/google/identity-toolkit-go-client/gitkit"
	"github.com/morras/gitserver"
	"github.com/morras/gitserver/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Login", func() {

	var login *gitserver.Login
	var tokenExtractorMock mocks.TokenExtractor

	BeforeEach(func() {
		login = gitserver.NewLogin(&userStoreMock, config, mocks.ContextProviderMock{}, &mocks.LoggerMock{}, &tokenExtractorMock)
	})

	Describe("Logging in", func() {
		Context("With a previous session", func() {

			var userID = "42"
			var sessionID = "Session id for previous session test"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				userStoreMock.Store.Users = []gitserver.User{
					{
						ID:    userID,
						Email: "test@tests.tildeslash.dk",
						Sessions: []gitserver.Session{
							createUserStoreSession(sessionID, 80),
						},
					},
				}

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should update the session with a new ID and expiration time", func() {
				By("Setting the cookie on the response")
				sessionCookie := sessionCookieFromResponse(res)
				Expect(sessionCookie.UserID).To(BeIdenticalTo(userID))
				Expect(sessionCookie.SessionID).ToNot(BeIdenticalTo(sessionID))

				By("Updating the user store with the same values")
				usersInStore := userStoreMock.Store.Users
				Expect(len(usersInStore)).To(BeIdenticalTo(1))
				userSessions := usersInStore[0].Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(1))
				userSession := userSessions[0]
				Expect(userSession.Value).To(BeIdenticalTo(sessionCookie.SessionID))
			})

			It("Should redirect to the logged in page", func() {
				ExpectRedirectTo(res, config.LoginRedirectURL)
			})
		})

		Context("With multiple valid sessions and a valid cookie", func() {
			var userID = "42"
			var sessionID1 = "Session id1 for previous session test"
			var sessionID2 = "Session id2 for previous session test"
			var sessionID3 = "Session id3 for previous session test"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				userStoreMock.Store.Users = []gitserver.User{
					{
						ID:    userID,
						Email: "test@tests.tildeslash.dk",
						Sessions: []gitserver.Session{
							createUserStoreSession(sessionID1, 80),
							createUserStoreSession(sessionID2, 80),
							createUserStoreSession(sessionID3, 80),
						},
					},
				}

				req := createRequestWithCookie(userID, sessionID2)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should only renew the session with the same id as the cookie", func() {
				userSessions := userStoreMock.Store.Users[0].Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(3))
				seenID1 := false
				seenID2 := false
				seenID3 := false
				seenNewID := false
				for _, session := range userSessions { //I do not really like this
					if session.Value == sessionID1 {
						if seenID1 {
							Fail(fmt.Sprintf("Already visited a session with id: %s", sessionID1))
						}
						seenID1 = true
					} else if session.Value == sessionID2 {
						if seenID2 {
							Fail(fmt.Sprintf("Already visited a session with id: %s", sessionID2))
						}
						seenID2 = true
					} else if session.Value == sessionID3 {
						if seenID3 {
							Fail(fmt.Sprintf("Already visited a session with id: %s", sessionID3))
						}
						seenID3 = true
					} else {
						if seenNewID {
							Fail(fmt.Sprintf("Already visited a session with a new id: %s", session.Value))
						}
						seenNewID = true
					}
				}
				Expect(seenID1).To(BeTrue())
				Expect(seenID2).To(BeFalse())
				Expect(seenID3).To(BeTrue())
				Expect(seenNewID).To(BeTrue())
			})
		})

		Context("Without a previous valid session but with a valid token", func() {
			var userID = "42"
			var sessionID1 = "Session id1 for previous session test"
			var sessionID2 = "Session id2 for previous session test"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = &gitkit.Token{
					LocalID: userID,
				}
				tokenExtractorMock.ExtractTokenCall.Returns.Error = nil

				userStoreMock.Store.Users = []gitserver.User{
					{
						ID:    userID,
						Email: "test@tests.tildeslash.dk",
						Sessions: []gitserver.Session{
							createUserStoreSession(sessionID1, -1),
							createUserStoreSession(sessionID2, -1),
						},
					},
				}

				req := createRequestWithCookie(userID, sessionID1)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should set a cookie and create a session in the user store", func() {
				sessionCookie := sessionCookieFromResponse(res)
				Expect(sessionCookie.UserID).To(BeIdenticalTo(userID))

				userSessions := userStoreMock.Store.Users[0].Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(1))
				userSession := userSessions[0]
				Expect(userSession.Value).To(BeIdenticalTo(sessionCookie.SessionID))
			})

			It("Should remove expired sessions from the user store", func() {
				userSessions := userStoreMock.Store.Users[0].Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(1))
				userSession := userSessions[0]
				Expect(userSession.Value).ToNot(BeIdenticalTo(sessionID1))
				Expect(userSession.Value).ToNot(BeIdenticalTo(sessionID2))
			})

			It("Should redirect to the logged in page", func() {
				ExpectRedirectTo(res, config.LoginRedirectURL)
			})
		})

		Context("With an invalid session cookie, but a valid token", func() {
			var userID = "42"
			var sessionID = "Session id"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = &gitkit.Token{
					LocalID: userID,
				}
				tokenExtractorMock.ExtractTokenCall.Returns.Error = nil

				userStoreMock.Store.Users = []gitserver.User{
					{
						ID:       userID,
						Email:    "test@tests.tildeslash.dk",
						Sessions: []gitserver.Session{},
					},
				}

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should set a new session cookie and create a session in the user store", func() {
				sessionCookie := sessionCookieFromResponse(res)
				Expect(sessionCookie.UserID).To(BeIdenticalTo(userID))

				userSessions := userStoreMock.Store.Users[0].Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(1))
				userSession := userSessions[0]
				Expect(userSession.Value).To(BeIdenticalTo(sessionCookie.SessionID))
			})

			It("Should redirect to the logged in page", func() {
				ExpectRedirectTo(res, config.LoginRedirectURL)
			})
		})

		Context("With an invalid session cookie and no token", func() {
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = nil
				tokenExtractorMock.ExtractTokenCall.Returns.Error = errors.New("Validation error")

				userStoreMock.Store.Users = []gitserver.User{
					{},
				}

				//Create and set cookie
				sc := "Session cookie is not a struct"

				cookieValue, _ := json.Marshal(sc)
				encodedCookieValue := base64.StdEncoding.EncodeToString(cookieValue)

				c := http.Cookie{
					Name:   gitserver.CookieName,
					Value:  encodedCookieValue,
					MaxAge: 1 * 60 * 60, //1 hour, this value is only important for the browser and has not meaning in the tests.
				}

				req := createDummyRequest()
				req.AddCookie(&c)

				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should delete the cookie and redirect to the log in page", func() {
				c := cookieFromResponse(res)

				Expect(c.Value).To(BeIdenticalTo("DELETED")) //We cannot get the expiration date, so the value have to do.
				Expect(len(userStoreMock.Store.Users[0].Sessions)).To(BeIdenticalTo(0))
				ExpectRedirectTo(res, config.URLPathToLogin)
			})
		})

		Context("With a user that does not exist in the UserStore", func() {

			var userID = "new user"
			var userEmail = "tester@test.tildeslash.dk"
			var sessionID = "Session id"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = &gitkit.Token{
					LocalID:       userID,
					Email:         userEmail,
					EmailVerified: true,
				}
				tokenExtractorMock.ExtractTokenCall.Returns.Error = nil

				userStoreMock.Store.Users = []gitserver.User{}
				userStoreMock.LookupUserCall.Returns.Err = gitserver.ErrUserNotFound

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should create a new user with a session in the user store", func() {
				sessionCookie := sessionCookieFromResponse(res)
				Expect(sessionCookie.UserID).To(BeIdenticalTo(userID))

				Expect(len(userStoreMock.Store.Users)).To(BeIdenticalTo(1))
				user := userStoreMock.Store.Users[0]
				Expect(user.ID).To(BeIdenticalTo(userID))
				Expect(user.Email).To(BeIdenticalTo(userEmail))

				userSessions := user.Sessions
				Expect(len(userSessions)).To(BeIdenticalTo(1))
			})

			It("Should redirect to the new user page", func() {
				ExpectRedirectTo(res, config.NewUserRedirectURL)
			})
		})

		Context("With a valid token with a new email", func() {
			var userID = "old user"
			var oldEmail = "oldTester@test.tildeslash.dk"
			var newEmail = "newTester@test.tildeslash.dk"
			var sessionID = "Session id"
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = &gitkit.Token{
					LocalID:       userID,
					Email:         newEmail,
					EmailVerified: true,
				}
				tokenExtractorMock.ExtractTokenCall.Returns.Error = nil

				userStoreMock.Store.Users = []gitserver.User{
					{
						ID:    userID,
						Email: oldEmail,
					},
				}
				userStoreMock.LookupUserCall.Returns.Err = gitserver.ErrUserNotFound

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should update the email of the user", func() {
				user := userStoreMock.Store.Users[0]
				Expect(user.ID).To(BeIdenticalTo(userID))
				Expect(user.Email).To(BeIdenticalTo(newEmail))
			})
		})

		Context("With invalid token and no cookie", func() {
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = nil
				tokenExtractorMock.ExtractTokenCall.Returns.Error = errors.New("Validation error")

				userStoreMock.Store.Users = []gitserver.User{}

				req := createDummyRequest()
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should redirect to the log in page", func() {
				ExpectRedirectTo(res, config.URLPathToLogin)
			})
		})

		Context("With an error from the UserStore", func() {
			var res *httptest.ResponseRecorder
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = &gitkit.Token{
					LocalID: "42",
				}
				tokenExtractorMock.ExtractTokenCall.Returns.Error = nil

				userStoreMock.Store.Users = []gitserver.User{}
				userStoreMock.LookupUserCall.Returns.Err = gitserver.NewUserStoreErr("cause")

				req := createDummyRequest()
				res = httptest.NewRecorder()
				login.LoginHandler(res, req)
			})

			It("Should redirect to the log in page", func() {
				ExpectRedirectTo(res, config.URLPathToLogin)
			})
		})
	})

	Describe("Logging out", func() {

		Describe("With a valid cookie", func() {
			var res *httptest.ResponseRecorder
			var userID = "42"
			var sessionID = "123"
			var otherUserID = "21"
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = nil
				tokenExtractorMock.ExtractTokenCall.Returns.Error = errors.New("Some error")

				userStoreMock.Store.Users = []gitserver.User{
					{
						ID: userID,
						Sessions: []gitserver.Session{
							createUserStoreSession("Prefix"+sessionID, 1),
							createUserStoreSession(sessionID, 1),
							createUserStoreSession(sessionID+"suffix", 1),
						},
					},
					{
						ID: otherUserID,
						Sessions: []gitserver.Session{
							createUserStoreSession(sessionID, 1),
						},
					},
				}
				userStoreMock.LookupUserCall.Returns.Err = gitserver.NewUserStoreErr("cause")

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LogoutHandler(res, req)
			})

			It("Should remove all sessions for the user in the user store", func() {
				user, _ := userStoreMock.LookupUser(nil, userID)
				Expect(len(user.Sessions)).To(BeIdenticalTo(0))
			})

			It("Should not affact other users in the user store", func() {
				user, _ := userStoreMock.LookupUser(nil, otherUserID)
				Expect(len(user.Sessions)).To(BeIdenticalTo(1))
			})

			It("It should delete the session cookie in the response", func() {
				c := cookieFromResponse(res)
				Expect(c.Value).To(BeIdenticalTo("DELETED")) //We cannot get the expiration date, so the value have to do.
			})

			It("Should redirect to the logged out page", func() {
				ExpectRedirectTo(res, config.LogoutRedirectURL)
			})
		})

		Describe("With an invalid cookie", func() {
			var res *httptest.ResponseRecorder
			var userID = "42"
			var sessionID = "123"
			BeforeEach(func() {
				//As we are not validating the token in the mock, the LocalID is enough
				tokenExtractorMock.ExtractTokenCall.Returns.Token = nil
				tokenExtractorMock.ExtractTokenCall.Returns.Error = errors.New("Some error")

				userStoreMock.Store.Users = []gitserver.User{
					{
						ID: userID,
						Sessions: []gitserver.Session{
							createUserStoreSession("Prefix"+sessionID, 1),
						},
					},
				}
				userStoreMock.LookupUserCall.Returns.Err = gitserver.NewUserStoreErr("cause")

				req := createRequestWithCookie(userID, sessionID)
				res = httptest.NewRecorder()
				login.LogoutHandler(res, req)
			})

			It("Clears the cookie", func() {
				c := cookieFromResponse(res)
				Expect(c.Value).To(BeIdenticalTo("DELETED")) //We cannot get the expiration date, so the value have to do.
			})

			It("Does not alter the user store", func() {
				user, _ := userStoreMock.LookupUser(nil, userID)
				Expect(len(user.Sessions)).To(BeIdenticalTo(1))
			})

		})
	})
})

func ExpectRedirectTo(res *httptest.ResponseRecorder, location string) {
	Expect(res.Code).To(BeIdenticalTo(http.StatusFound))
	Expect(res.HeaderMap.Get("Location")).To(BeIdenticalTo(location))
}

//This will only give the name and value of the cookie, and not the meta data like expiration
func cookieFromResponse(res *httptest.ResponseRecorder) *http.Cookie {
	//Temp request to make it easy to grab the cookie
	//Thanks to https://gist.github.com/jonnyreeves/17f91155a0d4a5d296d6 for the idea
	req := &http.Request{Header: http.Header{"Cookie": res.HeaderMap["Set-Cookie"]}}

	c, err := req.Cookie(gitserver.CookieName)
	if err != nil {
		Fail(fmt.Sprintf("Unable to get cookie from response %v", err))
	}

	return c
}

func sessionCookieFromResponse(res *httptest.ResponseRecorder) gitserver.SessionCookie {

	c := cookieFromResponse(res)
	sc, err := gitserver.SessionCookieFromCookie(c)
	if err != nil {
		Fail(fmt.Sprintf("Unable to get session cookie from cookie: %v", err))
	}

	return sc
}
