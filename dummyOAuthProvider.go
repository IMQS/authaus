package authaus

import (
	"encoding/json"
	"github.com/IMQS/log"
	"io"
	"net/http"
	"strings"
)

type dummyOAuthProvider struct {
	Log *log.Logger
}

func (d dummyOAuthProvider) bareHTTP(r *http.Request, token *oauthToken) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: 200,
	}
	user := &msaadUserJSON{
		DisplayName:       "Stay Archived",
		GivenName:         "Stay",
		Mail:              "Stay.Archived@example.com",
		Surname:           "Archived",
		MobilePhone:       "222 555 4328",
		UserPrincipalName: "Stay.Archived@example.com",
		ID:                "d1969c4b-b667-4bb5-9f9a-6fc0d0ec5083",
	}

	b, _ := json.Marshal(user)
	//str := fmt.Sprintf("%v", b)
	stringReader := strings.NewReader(string(b))
	stringReadCloser := io.NopCloser(stringReader)
	resp.Body = stringReadCloser
	return resp, nil
}

func (d dummyOAuthProvider) setLogger(logger *log.Logger) {
	d.Log = logger
}

func (d dummyOAuthProvider) entraRefreshHTTP(id string, provider *ConfigOAuthProvider, token oauthToken) (oauthToken, error) {
	newToken := oauthToken{
		AccessToken:      RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		TokenType:        token.TokenType,
		ExpiresIn:        120,
		Scope:            "refresh_token",
		RefreshToken:     RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		IDToken:          RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		Error:            "",
		ErrorDescription: "",
	}
	return newToken, nil
}

func (d dummyOAuthProvider) getAccessToken(provider *ConfigOAuthProvider, code, pkceVerifier string) (*oauthToken, error) {

	return &oauthToken{
		AccessToken:      RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		TokenType:        "Bearer",
		ExpiresIn:        3,
		Scope:            "refresh_token",
		RefreshToken:     RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		IDToken:          RandomString(1768, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"),
		Error:            "",
		ErrorDescription: "",
	}, nil
}
