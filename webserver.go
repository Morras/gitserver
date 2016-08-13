package gitserver

import (
	"net/http"
)

var loginHandler *Login

type Config struct {
	FilePathToFrontend string
	URLPathToApiRoot   string
	URLPathToLogin     string
	URLPathToLogout    string
	LoginRedirectURL   string
	LogoutRedirectURL  string
	NewUserRedirectURL string
	Audiences          []string
	SessionDuration    int
}

func Setup(taskAPI http.Handler, config Config, userStore UserStore, ctxProvider ContextProvider, logger ContextAwareLogger) {
	//Safe as it can only serve files from within the frontend directory
	//At least according to the source but the doc does not mention this
	fileHandler := http.FileServer(http.Dir(config.FilePathToFrontend))

	http.Handle(config.URLPathToApiRoot, taskAPI)

	loginHandler = NewLogin(userStore, config, ctxProvider, logger, &GitTokenExtractor{})

	http.HandleFunc(config.URLPathToLogin, loginHandler.LoginHandler)
	http.HandleFunc(config.URLPathToLogout, loginHandler.LogoutHandler)

	http.Handle("/", fileHandler)
}
