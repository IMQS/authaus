package authaus

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var (
	ErrHttpBasicBase64        = errors.New("HTTP Basic Authorization must be base64(identity:password). Error decoding base64")
	ErrHttpBasicIdentPassPair = errors.New("HTTP Basic Authorization must be base64(identity:password). Error separating identity:password")
)

// Understands a header of the form:
// Authentication: Basic BASE64(identity:password)
//
// If this is not 'Basic' authorization, then ("","",nil) is returned.
// Any other condition will result in a return either of
//    ("identity", "password", nil)
// or ("", "", error)
func HttpReadBasicAuth(r *http.Request) (identity, password string, err error) {
	auth := r.Header.Get("Authorization")
	if strings.Index(auth, "Basic ") != 0 {
		return
	}
	if decoded, e := base64.StdEncoding.DecodeString(auth[6:]); e != nil {
		err = ErrHttpBasicBase64
		return
	} else {
		parts := strings.Split(string(decoded), ":")
		if len(parts) == 2 {
			identity = parts[0]
			password = parts[1]
			err = nil
			return
		} else {
			err = ErrHttpBasicIdentPassPair
			return
		}
	}
}

// Reads the session cookie or the appropriate HTTP Authorization headers to determine
// whether this request is authorized. At present we do NOT read the Authorization headers,
// but instead use query parameters 'identity' and 'password'. This must change.
func HttpHandlerPrelude(config *ConfigHTTP, central *Central, r *http.Request) (*Token, error) {
	sessioncookie, _ := r.Cookie(config.CookieName)
	if sessioncookie != nil {
		return central.GetTokenFromSession(sessioncookie.Value)
	} else {
		// This is temporary. It should be in the Authorization header instead. By allowing credentials in the GET
		// request, you risk them being exposed in the HTTP server logs
		identity, password, eBasic := HttpReadBasicAuth(r)
		if eBasic != nil {
			return nil, eBasic
		} else {
			return central.GetTokenFromIdentityPassword(identity, password)
		}
	}
	// unreachable
	return nil, nil
}

// Runs the Prelude function, but before returning an error, sends an appropriate error response to the HTTP ResponseWriter.
// If this function returns a non-nil error, then it means that you should not send anything else to the http response.
func HttpHandlerPreludeWithError(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) (*Token, error) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		if strings.Index(err.Error(), ErrIdentityEmpty.Error()) == 0 {
			HttpSendTxt(w, http.StatusUnauthorized, err.Error())
		} else if err == ErrHttpBasicBase64 || err == ErrHttpBasicIdentPassPair {
			HttpSendTxt(w, http.StatusBadRequest, err.Error())
		} else {
			HttpSendTxt(w, http.StatusForbidden, err.Error())
		}
	}
	return token, err
}

// Handle the 'whoami' request, which is really just for debugging
func HttpHandlerWhoAmI(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	token, err := HttpHandlerPrelude(config, central, r)
	if err != nil {
		HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Success: Roles=%v", hex.EncodeToString(token.Permit.Roles)))
	}
}

func HttpSendTxt(w http.ResponseWriter, responseCode int, responseBody string) {
	w.WriteHeader(responseCode)
	w.Header().Add("Content-Type", "text/plain")
	fmt.Fprintf(w, "%v", responseBody)
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
// if authentication succeeds. You may want to use this as a template to write your own.
func HttpHandlerLogin(config *ConfigHTTP, central *Central, w http.ResponseWriter, r *http.Request) {
	identity, password, eBasic := HttpReadBasicAuth(r)
	if eBasic != nil {
		HttpSendTxt(w, http.StatusBadRequest, eBasic.Error())
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
