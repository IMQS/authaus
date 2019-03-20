package authaus

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrHttpBasicAuth     = errors.New("HTTP Basic Authorization must be base64(identity:password)")
	ErrHttpNotAuthorized = errors.New("No authorization information")
)

// HttpHandlerPrelude reads the session cookie or the HTTP "Basic" Authorization header to determine whether this request is authorized.
func HttpHandlerPrelude(config *ConfigHTTP, central *Central, r *http.Request) (*Token, error) {
	sessioncookie, _ := r.Cookie(config.CookieName)
	if sessioncookie != nil {
		return central.GetTokenFromSession(sessioncookie.Value)
	} else {
		return HttpHandlerBasicAuth(central, r)
	}
}

func HttpHandlerBasicAuth(central *Central, r *http.Request) (*Token, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrHttpNotAuthorized
	}

	identity, password, basicOK := r.BasicAuth()
	if !basicOK {
		return nil, ErrHttpBasicAuth
	} else {
		return central.GetTokenFromIdentityPassword(identity, password)
	}
}

// Runs the Prelude function, but before returning an error, sends an appropriate error response to the HTTP ResponseWriter.
// If this function returns a non-nil error, then it means that you should not send anything else to the http response.
func HttpHandlerPreludeWithError(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) (*Token, error) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		if strings.Index(err.Error(), ErrIdentityEmpty.Error()) == 0 {
			HttpSendTxt(w, http.StatusUnauthorized, err.Error())
		} else if err == ErrHttpBasicAuth {
			HttpSendTxt(w, http.StatusBadRequest, err.Error())
		} else if err == ErrHttpNotAuthorized {
			HttpSendTxt(w, http.StatusUnauthorized, err.Error())
		} else {
			HttpSendTxt(w, http.StatusForbidden, err.Error())
		}
	}
	return token, err
}

// HttpHandlerWhoAmI handles the 'whoami' request, which is really just for debugging
func HttpHandlerWhoAmI(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Success: Roles=%v", hex.EncodeToString(token.Permit.Roles)))
	}
}

func HttpSendTxt(w http.ResponseWriter, responseCode int, responseBody string) {
	w.Header().Add("Content-Type", "text/plain")
	w.Header().Add("Cache-Control", "no-cache, no-store, must revalidate")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Expires", "0")
	w.WriteHeader(responseCode)
	fmt.Fprintf(w, "%v", responseBody)
}

// HttpHandlerLogin handles the 'login' request, sending back a session token (via Set-Cookie),
// if authentication succeeds. You may want to use this as a template to write your own.
func HttpHandlerLogin(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	identity, password, basicOK := r.BasicAuth()
	if !basicOK {
		HttpSendTxt(w, http.StatusBadRequest, ErrHttpBasicAuth.Error())
		return
	}
	if sessionkey, token, err := central.Login(identity, password); err != nil {
		HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		cookie := &http.Cookie{
			Name:    config.CookieName,
			Value:   sessionkey,
			Path:    "/",
			Expires: token.Expires,
			Secure:  config.CookieSecure,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
	}
}

func HttpHandlerLogout(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	sessioncookie, _ := r.Cookie(config.CookieName)
	if sessioncookie != nil {
		err := central.Logout(sessioncookie.Value)
		if err != nil {
			HttpSendTxt(w, http.StatusServiceUnavailable, err.Error())
		}
	}
	HttpSendTxt(w, http.StatusOK, "")
}

// Run as a standalone HTTP server. This just wires up the various HTTP handler functions and starts
// a listener. You will probably want to add your own entry points and do that yourself instead of using this.
// This function is useful for demo/example purposes.
func RunHttp(config *ConfigHTTP, central *Central) error {
	makehandler := func(actual func(*ConfigHTTP, *Central, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			actual(config, central, w, r)
		}
	}

	http.HandleFunc("/whoami", makehandler(HttpHandlerWhoAmI))
	http.HandleFunc("/login", makehandler(HttpHandlerLogin))
	http.HandleFunc("/logout", makehandler(HttpHandlerLogout))

	fmt.Printf("Trying to listen on %v:%v\n", config.Bind, config.Port)
	if err := http.ListenAndServe(config.Bind+":"+ config.Port, nil); err != nil {
		return err
	}

	return nil
}

func RunHttpFromConfig(config *Config) error {
	if central, err := NewCentralFromConfig(config); err != nil {
		return err
	} else {
		return RunHttp(&config.HTTP, central)
	}
}
