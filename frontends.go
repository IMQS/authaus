package authaus

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
)

// Reads the session cookie or the appropriate HTTP Authorization headers to determine
// whether this request is authorized. At present we do NOT read the Authorization headers,
// but instead use query parameters 'identity' and 'password'. This must change.
func HttpHandlerPrelude(config *ConfigHTTP, central *Central, r *http.Request) (*Token, error) {
	sessioncookie, _ := r.Cookie(config.CookieName)
	if sessioncookie != nil {
		return central.GetTokenFromSession(sessioncookie.Value)
	} else {
		// This is temporary. It should be in the Authorization header instead
		identity := r.URL.Query().Get("identity")
		password := r.URL.Query().Get("password")
		return central.GetTokenFromIdentityPassword(identity, password)
	}
	// unreachable
	return nil, nil
}

// Runs the Prelude function, but before returning an error, sends an appropriate error response to the HTTP ResponseWriter.
func HttpHandlerPreludeWithError(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) (*Token, error) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, err.Error())
	}
	return token, err
}

// Handle the 'whoami' request, which is really just for debugging
func HttpHandlerWhoAmI(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Error: %v", err)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "Success: Roles=%v", hex.EncodeToString(token.Permit.Roles))
	}
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
// if authentication succeeds. You may want to use this as a template to write your own.
func HttpHandlerLogin(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	identity := r.URL.Query().Get("identity")
	password := r.URL.Query().Get("password")
	if sessionkey, token, err := central.Login(identity, password); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "%v", err)
	} else {
		// TODO: Set Cookie's "Secure: true" when appropriate
		// It should actually be hard to send a cookie with Secure: false.
		// One way might be to use r.TLS, but I haven't tested that yet.
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

	fmt.Printf("Listening on %v:%v\n", config.Bind, config.Port)
	if err := http.ListenAndServe(config.Bind+":"+strconv.Itoa(config.Port), nil); err != nil {
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
	// unreachable
	return nil
}
