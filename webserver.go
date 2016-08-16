package gitserver

import "net/http"

var loginHandler *Login

type Config struct {
	URLPathToLogin     string
	URLPathToLogout    string
	LoginRedirectURL   string
	LogoutRedirectURL  string
	NewUserRedirectURL string
	Audiences          []string
	SessionDuration    int
	SecureCookies      bool
}

func Setup(serveMux *http.ServeMux, config Config, userStore UserStore, ctxProvider ContextProvider, logger ContextAwareLogger) {
	loginHandler = NewLogin(userStore, config, ctxProvider, logger, &GitTokenExtractor{})
	serveMux.HandleFunc(config.URLPathToLogin, loginHandler.LoginHandler)
	serveMux.HandleFunc(config.URLPathToLogout, loginHandler.LogoutHandler)
}
