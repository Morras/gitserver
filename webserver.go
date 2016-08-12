package gitserver

import (
	"net/http"
)

var loginHandler login

type Config struct {
	FilePathToFrontend string
	UrlPathToApiRoot   string
	UrlPathToLogin     string
	UrlPathToLogout    string
	LoginRedirectUrl   string
	LogoutRedirectUrl  string
	Audiences          []string
	SessionDuration    int
}

func Setup(taskAPI http.Handler, config Config, userStore UserStore, ctxProvider ContextProvider, logger ContextAwareLogger) {
	//Safe as it can only serve files from within the frontend directory
	//At least according to the source but the doc does not mention this
	fileHandler := http.FileServer(http.Dir(config.FilePathToFrontend))

	http.Handle(config.UrlPathToApiRoot, taskAPI)

	loginHandler = login{userStore: userStore, config: config, ctxProvider: ctxProvider, logger: logger}

	http.HandleFunc(config.UrlPathToLogin, loginHandler.loginHandler)
	http.HandleFunc(config.UrlPathToLogout, loginHandler.logoutHandler)

	http.Handle("/", fileHandler)
}
