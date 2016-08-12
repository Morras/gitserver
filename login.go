package gitserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/satori/go.uuid"

	"golang.org/x/net/context"

	"encoding/json"

	"errors"

	"encoding/base64"
	"github.com/google/identity-toolkit-go-client/gitkit"
)

const (
	CookieName = "gitserver-session"
)

var ErrSessionCookieNotFound = errors.New("Session cookie not found")

type SessionCookie struct {
	UserID    string
	SessionID string
}

type login struct {
	userStore   UserStore
	config      Config
	ctxProvider ContextProvider
	logger      ContextAwareLogger
}

func (l *login) loginHandler(res http.ResponseWriter, req *http.Request) {

	ctx := l.contextFromRequest(req)

	l.logger.Debugf(ctx, "Serving logged in")

	/* Check if user was already logged in */
	sc, err := sessionCookieFromRequest(req)
	if err != nil && err != ErrSessionCookieNotFound {
		l.logAndServeError(ctx, fmt.Sprintf("Error getting session cookie from request %v", err), err, res)
		return
	}

	if err != ErrSessionCookieNotFound {
		user, _ := l.userStore.LookupUser(ctx, sc.UserID)
		if user != nil {
			for _, s := range user.Sessions {
				if s.Value == sc.SessionID && !isExpired(s) {
					//Renew the session
					l.renewSessionCookie(user, ctx, res)
					http.Redirect(res, req, l.config.LoginRedirectUrl, http.StatusFound)
					return
				}
			}
		}
	}

	//If the user does not have a valid session cookie, we must
	//identify the user by the token

	/* Get token */
	token, err := l.extractToken(req)
	if err != nil {
		l.logger.Errorf(ctx, "%v", err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	/* Get user or create a new one if none exists */
	user, err := l.userStore.LookupUser(ctx, token.LocalID)
	if err != nil && err != ErrUserNotFound {
		l.logger.Errorf(ctx, "Error getting user with id %v. %v", token.LocalID, err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	if err == ErrUserNotFound {
		user = &User{ID: token.LocalID, Email: token.Email}
	} else if token.EmailVerified {
		user.Email = token.Email
	}

	//Create a new session for the user
	if err := l.renewSessionCookie(user, ctx, res); err != nil {
		l.logAndServeError(ctx, fmt.Sprintf("Error marshalling cookie %v %v", sc, err), err, res)
		return
	}

	http.Redirect(res, req, l.config.LoginRedirectUrl, http.StatusFound)
	return
}

func (l *login) logoutHandler(res http.ResponseWriter, req *http.Request) {
	ctx := l.contextFromRequest(req)

	l.logger.Debugf(ctx, "Serving logged out")

	l.deleteSessionCookie(res)

	token, err := l.extractToken(req)
	if err != nil {
		l.logger.Infof(ctx, "%v", err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	user, err := l.userStore.LookupUser(ctx, token.LocalID)
	if err != nil { //TODO err could also just be that the user does not exists
		l.logger.Errorf(ctx, "Error getting user with id %v. %v", token.LocalID, err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	//This logs the user out of all devices, consider only doing it for the one
	user.Sessions = []Session{}
	l.userStore.UpdateUser(ctx, user)

	http.Redirect(res, req, l.config.LogoutRedirectUrl, http.StatusFound)
}

func (l *login) contextFromRequest(req *http.Request) context.Context {
	return l.ctxProvider.ContextFromRequest(req)
}

func (l *login) extractToken(req *http.Request) (*gitkit.Token, error) {

	ctx := l.contextFromRequest(req)

	config := gitkit.Config{}
	client, err := gitkit.New(ctx, &config)
	if err != nil {
		return nil, err
	}

	ts := client.TokenFromRequest(req)
	audience := l.config.Audiences

	token, err := client.ValidateToken(ctx, ts, audience)

	if err != nil {
		err = fmt.Errorf("Unable to validate token %v, error %v", ts, err)
	}

	return token, err
}

func (l *login) renewSessionCookie(user *User, ctx context.Context, res http.ResponseWriter) error {

	validSessions := []Session{}

	//Clean up sessions by removing expired ones
	for _, s := range user.Sessions {
		if isExpired(s) {
			validSessions = append(validSessions, s)
		}
	}

	//Create a new session for the user
	d := time.Hour * time.Duration(l.config.SessionDuration)
	ed := time.Now().Add(d)
	session := Session{Value: uuid.NewV4().String(), Expires: ed}

	user.Sessions = append(validSessions, session)

	l.userStore.UpdateUser(ctx, user)

	//Create and set cookie
	sc := SessionCookie{
		UserID:    user.ID,
		SessionID: session.Value,
	}

	cookieValue, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	encodedCookieValue := base64.StdEncoding.EncodeToString(cookieValue)

	c := http.Cookie{
		Name:    CookieName,
		Value:   string(encodedCookieValue),
		Expires: session.Expires,
		MaxAge:  l.config.SessionDuration * 60 * 60, //hours to seconds
		//TODO Should probably add secure once dev is done and I got a https test up and running
	}
	http.SetCookie(res, &c)

	return nil
}

func (l *login) deleteSessionCookie(res http.ResponseWriter) {
	c := http.Cookie{
		Name:   CookieName,
		Value:  "",
		MaxAge: -1, //Delete it now
		//TODO Should probably add secure once dev is done and I got a https test up and running
	}
	http.SetCookie(res, &c)
}

func (l *login) logAndServeError(ctx context.Context, logMessage string, err error, res http.ResponseWriter) {
	l.logger.Errorf(ctx, logMessage)
	res.WriteHeader(http.StatusInternalServerError)
}

func sessionCookieFromRequest(req *http.Request) (SessionCookie, error) {
	sc := SessionCookie{}
	cookie, err := req.Cookie(CookieName)
	if err == http.ErrNoCookie {
		return sc, ErrSessionCookieNotFound
	}
	decodedCookieValue, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return sc, err
	}
	if err := json.Unmarshal(decodedCookieValue, &sc); err != nil {
		error := err.Error()
		error = error + ""
		return sc, err
	}
	return sc, nil
}

func isExpired(s Session) bool {
	delta := s.Expires.Sub(time.Now()).Nanoseconds()
	return delta < 0
}
