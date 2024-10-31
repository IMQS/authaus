package authaus

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestOAuth_Initialize(t *testing.T) {
	c := getCentralMSAAD(t, defaultOauth(), defaultMsaad())
	assert.NotNil(t, c)

	req, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}
	req.Form = make(map[string][]string)
	req.Form.Add("provider", "test")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(c.OAuth.HttpHandlerOAuthStart)
	handler.ServeHTTP(rr, req)

	// Check the status code and other assertions
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Response body: %v", rr.Body.String())
	} else {
		t.Logf("Response body: %v", rr.Body.String())
	}
}

func TestOAuth_StartFinish(t *testing.T) {
	nextUserId = 0
	c := getCentralMSAAD(t, defaultOauth(), defaultMsaad())
	assert.NotNil(t, c)
	identities, _ := c.userStore.GetIdentities(GetIdentitiesFlagNone)
	assert.Equal(t, 3, len(identities))

	// Do the full cycle, so that the challenges / sessions tie up
	req, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}
	req.Form = make(map[string][]string)
	req.Form.Add("provider", "test")

	rr := httptest.NewRecorder()
	handlerOAuthStart := http.HandlerFunc(c.OAuth.HttpHandlerOAuthStart)
	handlerOAuthStart.ServeHTTP(rr, req)

	// Check the status code and other assertions
	assert.Equal(t, http.StatusFound, rr.Code, "Handler returned wrong status code")
	t.Logf("Response body: %v", rr.Body.String())

	// parse the body to get the parameters
	// state is session id for the OAuth challenge
	state := getValue(rr.Body.String(), "state")
	code := getValue(rr.Body.String(), "code_challenge")
	t.Logf("State: %v, Code: %v", state, code)

	// test challenge
	provider, codeVerifier, e := c.OAuth.OAuthDB.getChallenge(state)
	assert.Nil(t, e, "Error should be nil")
	assert.Equal(t, "test", provider, "Provider should be test")
	// here the codeVerifier is related to the code challenge via sha256 hashing
	// we can use this to test if the code challenge is correct:
	sum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, code, challenge, "Hashed code challenge should be match verifier")

	// Now we need to simulate the OAuth callback
	req2, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}

	req2.Form = make(map[string][]string)
	req2.Form.Add("provider", "test")
	req2.Form.Add("state", state)
	req2.Form.Add("code", code)

	rr2 := httptest.NewRecorder()
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectCodeToState(code, state)
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectStateToUser(state, "Stay.Archived@example.com")
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectEmailToUser("Stay.Archived@example.com", &msaadUserJSON{
		DisplayName:       "Stay Archived",
		GivenName:         "Stay",
		Mail:              "Stay.Archived@example.com",
		Surname:           "Archived",
		MobilePhone:       "222 555 4328",
		UserPrincipalName: "Stay.Archived@example.com",
		ID:                "d1969c4b-b667-4bb5-9f9a-6fc0d0ec5083",
	})
	handlerOAuthEnd := http.HandlerFunc(c.OAuth.HttpHandlerOAuthFinish)
	handlerOAuthEnd.ServeHTTP(rr2, req2)
	// test sessions (at least 1, NEW)
	s, e := c.OAuth.OAuthDB.getSessions()
	assert.Nil(t, e, "Error should be nil")
	assert.Equal(t, 1, len(s), "Sessions should be 1")
	found := false
	for _, session := range s {
		if session.id == state {
			found = true
		}
	}
	assert.True(t, found, "Session should be found")
	// test challenge (should be deleted)
	_, _, e = c.OAuth.OAuthDB.getChallenge(state)
	assert.NotNil(t, e, "Error should not be nil")

	// Check the status code and other assertions
	assert.Equal(t, http.StatusInternalServerError, rr2.Code, "Handler returned wrong status code")
	assert.Contains(t, rr2.Body.String(), "archived", "Response body should contain 'archived'")
	t.Logf("Response body: %v", rr2.Body.String())

	// TODO : don't test cleanup here, the timing is complicated
	// rather test the cleanups in a separate test, targeting the methods directly
	// Sessions only expire or get deleted on error...
}

func TestOAuth_NoArchiveCreateUser(t *testing.T) {
	// Setup cases for combinations of allowCreateUser and allowarchive
	nextUserId = 0
	oauthconfig := defaultOauth()
	oauthconfig.Providers["test"].AllowCreateUser = false
	assert.Equal(t, false, oauthconfig.Providers["test"].AllowCreateUser, "AllowCreateUser should be false")
	msaadconfig := defaultMsaad()
	msaadconfig.AllowArchiveUser = false
	assert.Equal(t, false, msaadconfig.AllowArchiveUser, "AllowArchiveUser should be false")

	c := getCentralMSAAD(t, oauthconfig, msaadconfig)
	assert.NotNil(t, c)
	identities, _ := c.userStore.GetIdentities(GetIdentitiesFlagNone)
	assert.Equal(t, 3, len(identities))

	// Do the full cycle, so that the challenges / sessions tie up
	req, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}
	req.Form = make(map[string][]string)
	req.Form.Add("provider", "test")

	rr := httptest.NewRecorder()
	handlerOAuthStart := http.HandlerFunc(c.OAuth.HttpHandlerOAuthStart)
	handlerOAuthStart.ServeHTTP(rr, req)
	state := getValue(rr.Body.String(), "state")
	code := getValue(rr.Body.String(), "code_challenge")

	// get challenge
	//_, codeVerifier, _ := c.OAuth.OAuthDB.getChallenge(state)
	// here the codeVerifier is related to the code challenge via sha256 hashing
	// we can use this to test if the code challenge is correct:
	//sum := sha256.Sum256([]byte(codeVerifier))
	//challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	//assert.Equal(t, code, challenge, "Hashed code challenge should be match verifier")
	// Now we need to simulate the OAuth callback
	req2, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}

	req2.Form = make(map[string][]string)
	req2.Form.Add("provider", "test")
	req2.Form.Add("state", state)
	req2.Form.Add("code", code)

	rr2 := httptest.NewRecorder()
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectStateToUser(state, "Jane.Doe@example.com")
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectCodeToState(code, state)
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectEmailToUser("Stay.Archived@example.com", &msaadUserJSON{
		DisplayName:       "Stay Archived",
		GivenName:         "Stay",
		Mail:              "Stay.Archived@example.com",
		Surname:           "Archived",
		MobilePhone:       "222 555 4328",
		UserPrincipalName: "Stay.Archived@example.com",
		ID:                "d1969c4b-b667-4bb5-9f9a-6fc0d0ec5083",
	})
	c.OAuth.OAuthProvider.(*dummyOAuthProvider).connectEmailToUser("Jane.Doe@example.com", &msaadUserJSON{
		DisplayName:       "Jane Doe",
		GivenName:         "Jane",
		Mail:              "Jane.Doe@example.com",
		Surname:           "Doe",
		MobilePhone:       "222 555 4328",
		UserPrincipalName: "Jane.Doe@example.com",
		ID:                "12345678-1234-1234-1234-123456789012",
	})

	fmt.Printf("State: %v, Code: %v\n", state, code)
	handlerOAuthEnd := http.HandlerFunc(c.OAuth.HttpHandlerOAuthFinish)
	handlerOAuthEnd.ServeHTTP(rr2, req2)

	// Check the status code and other assertions
	assert.Equal(t, http.StatusOK, rr2.Code, "Handler returned wrong status code")
	t.Logf("Response body: %v", rr2.Body.String())
	assert.Contains(t, rr2.Body.String(), "OAuth login success")
	assert.Contains(t, rr2.Body.String(), "IsNewUser = false")
	assert.Contains(t, rr2.Body.String(), "UserId = 2")
}

// getValue extracts the value of an identifier from a string
func getValue(sourceString string, identifier string) string {
	r := regexp.MustCompile(identifier + `=([[:alnum:]\-_~\.]+)`).FindStringSubmatch(sourceString)
	if len(r) > 1 {
		return r[1]
	}
	return ""
}
