package authaus

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/log"
	"io"
	"net/http"
	"strings"
)

type dummyOAuthProvider struct {
	Log            *log.Logger
	CodeToStateMap map[string]string
	StateToUser    map[string]string
	TokenToCode    map[string]string
	EmailToUser    map[string]*msaadUserJSON
}

func (d *dummyOAuthProvider) connectCodeToState(code string, state string) {
	if d.CodeToStateMap == nil {
		d.CodeToStateMap = make(map[string]string)
	}
	d.CodeToStateMap[code] = state
}

func (d *dummyOAuthProvider) bareHTTP(r *http.Request, token *oauthToken) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: 200,
	}
	var user *msaadUserJSON
	code := d.TokenToCode[token.AccessToken]
	state := d.CodeToStateMap[code]
	useremail := d.StateToUser[state]
	user = d.EmailToUser[useremail]
	b, _ := json.Marshal(user)
	//str := fmt.Sprintf("%v", b)
	stringReader := strings.NewReader(string(b))
	stringReadCloser := io.NopCloser(stringReader)
	resp.Body = stringReadCloser
	return resp, nil
}

func (d *dummyOAuthProvider) setLogger(logger *log.Logger) {
	d.Log = logger
}

func (d *dummyOAuthProvider) entraRefreshHTTP(id string, provider *ConfigOAuthProvider, token oauthToken) (oauthToken, error) {
	fmt.Printf("entraRefreshHTTP: %s\n", id)
	return token, nil
	//newToken := oauthToken{
	//	AccessToken:      RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
	//	TokenType:        token.TokenType,
	//	ExpiresIn:        120,
	//	Scope:            "refresh_token",
	//	RefreshToken:     RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
	//	IDToken:          RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
	//	Error:            "",
	//	ErrorDescription: "",
	//}
	//return newToken, nil
}

func (d *dummyOAuthProvider) getAccessToken(provider *ConfigOAuthProvider, code, pkceVerifier string) (*oauthToken, error) {
	// pick token, based on code
	token := &oauthToken{
		AccessToken:      RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		TokenType:        "Bearer",
		ExpiresIn:        150,
		Scope:            "refresh_token",
		RefreshToken:     RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		IDToken:          RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		Error:            "",
		ErrorDescription: "",
	}
	if d.TokenToCode == nil {
		d.TokenToCode = make(map[string]string)
	}
	d.TokenToCode[token.AccessToken] = code
	fmt.Println("getAccessToken")
	fmt.Printf("code: %s\n", code)
	fmt.Printf("accestoken: %s\n", token.AccessToken)
	return token, nil
}

func (d *dummyOAuthProvider) connectStateToUser(state string, user string) {
	// connect state to user
	if d.StateToUser == nil {
		d.StateToUser = make(map[string]string)
	}
	d.StateToUser[state] = user
}

func (d *dummyOAuthProvider) connectEmailToUser(s string, m *msaadUserJSON) {
	if d.EmailToUser == nil {
		d.EmailToUser = make(map[string]*msaadUserJSON)
	}
	d.EmailToUser[s] = m
}
