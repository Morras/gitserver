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
)

const (
	CookieName = "gitserver-session"
)

var ErrSessionCookieNotFound = errors.New("Session cookie not found")

type SessionCookie struct {
	UserID    string
	SessionID string
}

type Login struct {
	userStore      UserStore
	config         Config
	ctxProvider    ContextProvider
	logger         ContextAwareLogger
	tokenExtractor TokenExtractor
}

func NewLogin(userStore UserStore, config Config, ctxProvider ContextProvider, logger ContextAwareLogger, tokenExtractor TokenExtractor) *Login {
	return &Login{userStore: userStore, config: config, ctxProvider: ctxProvider, logger: logger, tokenExtractor: tokenExtractor}
}

func (l *Login) LoginHandler(res http.ResponseWriter, req *http.Request) {

	ctx := l.contextFromRequest(req)

	l.logger.Debugf(ctx, "Serving logged in")

	/* Check if user was already logged in */
	sc, err := sessionCookieFromRequest(req)
	if err != nil && err != ErrSessionCookieNotFound {
		l.logger.Errorf(ctx, "%v", err)
		deleteSessionCookie(res)
		http.Redirect(res, req, l.config.URLPathToLogin, http.StatusFound)
		return
	}

	if err != ErrSessionCookieNotFound {
		user, _ := l.userStore.LookupUser(ctx, sc.UserID)
		if user != nil {
			for _, s := range user.Sessions {
				if s.Value == sc.SessionID && !isExpired(s) {
					l.renewSessionCookie(user, ctx, res, sc.SessionID)
					http.Redirect(res, req, l.config.LoginRedirectURL, http.StatusFound)
					return
				}
			}
		}
	}

	//If the user does not have a valid session cookie, we must
	//identify the user by the token

	/* Get token */
	token, err := l.tokenExtractor.ExtractToken(req, ctx, l.config.Audiences)
	if err != nil {
		l.logger.Errorf(ctx, "%v", err)
		http.Redirect(res, req, l.config.URLPathToLogin, http.StatusFound)
		return
	}

	/* Get user or create a new one if none exists */
	user, err := l.userStore.LookupUser(ctx, token.LocalID)
	if err != nil && err != ErrUserNotFound {
		l.logger.Errorf(ctx, "Error getting user with id %v. %v", token.LocalID, err)
		http.Redirect(res, req, l.config.URLPathToLogin, http.StatusFound)
		return
	}
	isNewUser := false
	if err == ErrUserNotFound {
		user = &User{ID: token.LocalID, Email: token.Email}
		isNewUser = true
	} else if token.EmailVerified {
		user.Email = token.Email
	}

	//Create a new session for the user
	if err := l.renewSessionCookie(user, ctx, res, ""); err != nil {
		l.logger.Errorf(ctx, fmt.Sprintf("Error marshalling cookie %v %v", sc, err))
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if isNewUser {
		http.Redirect(res, req, l.config.NewUserRedirectURL, http.StatusFound)
	} else {
		http.Redirect(res, req, l.config.LoginRedirectURL, http.StatusFound)
	}
	return
}

func (l *Login) LogoutHandler(res http.ResponseWriter, req *http.Request) {
	ctx := l.contextFromRequest(req)
	l.logger.Debugf(ctx, "Serving logged out")

	if sc, err := sessionCookieFromRequest(req); err == nil {
		user, _ := l.userStore.LookupUser(ctx, sc.UserID)
		if user != nil {
			for _, s := range user.Sessions {
				if s.Value == sc.SessionID && !isExpired(s) {
					//This logs the user out of all devices, consider only doing it for the one
					user.Sessions = []Session{}
					l.userStore.UpdateUser(ctx, user)
					break
				}
			}
		}
	}
	deleteSessionCookie(res)

	http.Redirect(res, req, l.config.LogoutRedirectURL, http.StatusFound)
}

func (l *Login) contextFromRequest(req *http.Request) context.Context {
	return l.ctxProvider.ContextFromRequest(req)
}

func (l *Login) renewSessionCookie(user *User, ctx context.Context, res http.ResponseWriter, oldSessionID string) error {

	validSessions := []Session{}

	//Clean up sessions by removing expired ones, as well as the one we are replacing
	for _, s := range user.Sessions {
		if !isExpired(s) && s.Value != oldSessionID {
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

func deleteSessionCookie(res http.ResponseWriter) {
	c := http.Cookie{
		Name:   CookieName,
		Value:  "DELETED",
		MaxAge: -1, //Delete it now
		//TODO Should probably add secure once dev is done and I got a https test up and running
	}
	http.SetCookie(res, &c)
}

func sessionCookieFromRequest(req *http.Request) (SessionCookie, error) {
	cookie, err := req.Cookie(CookieName)
	if err == http.ErrNoCookie {
		return SessionCookie{}, ErrSessionCookieNotFound
	}

	return SessionCookieFromCookie(cookie)
}

func SessionCookieFromCookie(cookie *http.Cookie) (SessionCookie, error) {
	sc := SessionCookie{}

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
