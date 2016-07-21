package gitserver

import (
	"log" //TODO take log as config instead if you want to use a different one, like app engine

	gaeLog "google.golang.org/appengine/log" //TODO get rid of this if possible

	"fmt"
	"net/http"
	"time"

	"github.com/satori/go.uuid"

	"golang.org/x/net/context"

	"encoding/json"

	"github.com/google/identity-toolkit-go-client/gitkit"
)

const (
	cookieName = "gitserver-session"
)

type sessionCookie struct {
	UserID    string
	SessionID string
}

type login struct {
	userStore   UserStore
	config      Config
	ctxProvider ContextProvider
}

func (l *login) contextFromRequest(req *http.Request) context.Context {
	return l.ctxProvider.ContextFromRequest(req)
}

func sessionCookieFromRequest(req *http.Request) (sessionCookie, error) {
	var sc sessionCookie
	cookie, err := req.Cookie(cookieName)
	if err == http.ErrNoCookie {
		return sc, nil
	}
	if err := json.Unmarshal([]byte(cookie.Value), &sc); err != nil {
		return sc, err
	}
	return sc, nil
}

func (l *login) loginHandler(res http.ResponseWriter, req *http.Request) {

	ctx := l.contextFromRequest(req)

	gaeLog.Infof(ctx, "Serving logged in")

	sc, err := sessionCookieFromRequest(req)
	if err != nil { //Not a problem if the err is that the cookie does not exists
		gaeLog.Errorf(ctx, "Error getting session cookie from request %v", err)
		logAndServeError(fmt.Sprintf("Error getting session cookie from request %v", err), err, res)
		return
	}

	//Check if user was already
	userSessions := l.userStore.Sessions(ctx, sc.UserID)
	for _, s := range userSessions {
		if s.Value == sc.SessionID && !isExpired(s) {
			http.Redirect(res, req, l.config.LoginRedirectUrl, http.StatusFound)
			return
		}
	}

	token, err := l.extractToken(req)
	if err != nil {
		gaeLog.Errorf(ctx, "%v", err)
		log.Printf("%v", err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	user, err := l.userStore.LookupUser(ctx, token.LocalID)
	if err != nil { //TODO err could also just be that the user does not exists
		gaeLog.Errorf(ctx, "Error getting user with id %v. %v", token.LocalID, err)
		log.Printf("Error getting user with id %v. %v", token.LocalID, err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	if token.EmailVerified { //Or the user is new, but then also set id
		user.Email = token.Email
	}

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
	sc = sessionCookie{
		UserID:    user.ID,
		SessionID: session.Value,
	}

	cookieValue, err := json.Marshal(sc)
	if err != nil {
		logAndServeError(fmt.Sprintf("Error marshalling cookie %v %v", sc, err), err, res)
		return
	}

	c := http.Cookie{
		Name:    "cookieName",
		Value:   string(cookieValue),
		Expires: session.Expires,
		MaxAge:  l.config.SessionDuration * 60 * 60, //hours to seconds
		//Should probably add secure once dev is done and I got a https test up and running
	}
	http.SetCookie(res, &c)

	http.Redirect(res, req, l.config.LoginRedirectUrl, http.StatusFound)
	return
}

func logAndServeError(logMessage string, err error, res http.ResponseWriter) {
	log.Print(logMessage)
	res.WriteHeader(http.StatusInternalServerError)
}

func isExpired(s Session) bool {
	return s.Expires.Sub(time.Now()).Nanoseconds() > 0
}

func (l *login) extractToken(req *http.Request) (*gitkit.Token, error) {

	ctx := l.contextFromRequest(req)

	config := gitkit.Config{}
	client, err := gitkit.New(ctx, &config)
	if err != nil {
		return nil, err
	}
	log.Printf("client: %v", client)

	ts := client.TokenFromRequest(req)
	audience := l.config.Audiences

	token, err := client.ValidateToken(ctx, ts, audience)

	if err != nil {
		err = fmt.Errorf("Unable to validate token %v, error %v", ts, err)
	}

	return token, err
}

func (l *login) logoutHandler(res http.ResponseWriter, req *http.Request) {

	ctx := l.contextFromRequest(req)
	
	gaeLog.Errorf(ctx, "Serving logged out")

	token, err := l.extractToken(req)
	if err != nil {
		log.Printf("%v", err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	user, err := l.userStore.LookupUser(ctx, token.LocalID)
	if err != nil { //TODO err could also just be that the user does not exists
		log.Printf("Error getting user with id %v. %v", token.LocalID, err)
		res.WriteHeader(http.StatusUnauthorized)
		return //TODO I should probably do something a bit more intelligent like displaying the login page again
	}

	user.Sessions = []Session{}
	l.userStore.UpdateUser(ctx, user)

	http.Redirect(res, req, l.config.LogoutRedirectUrl, http.StatusFound)
}
