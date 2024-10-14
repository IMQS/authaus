package authaus

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

/*
GET https://graph.microsoft.com/v1.0/me

	{
		"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users/$entity",
		"businessPhones":[],
		"displayName":"Ben Harper",
		"givenName":"Ben",
		"jobTitle":null,
		"mail":null,
		"mobilePhone":null,
		"officeLocation":null,
		"preferredLanguage":null,
		"surname":"Harper",
		"userPrincipalName":"ben.harper@dtpwemerge.onmicrosoft.com",
		"id":"daf5d9a0-cf27-4913-9a7f-eafd5b590a45"
	}
*/

/*
Example:

	{
		"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1Q...",
		"token_type": "Bearer",
		"expires_in": 3599,
		"scope": "https%3A%2F%2Fgraph.microsoft.com%2Fmail.read",
		"refresh_token": "AwABAAAAvPM1KaPlrEqdFSBzjqfTGAMxZGUTdM0t4B4...",
		"id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctOD...",
	}
*/

type OAuthProvider struct {
}

func (x *OAuthProvider) getUserProfile(id string, provider *ConfigOAuthProvider) (*OAuthUserProfile, error) {
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far
	if provider.Type != OAuthProviderMSAAD {
		return nil, fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
	}

	ms := msaadUserProfile{}

	// be careful when using /me as below. It will provide a different UPN
	// than other graph endpoints. For example, /users/{id} will generally provide
	// the user's home tenant UPN appended with other information, while
	// /me will provide the user's home tenant UPN only. See similar comments
	// in msaad.go.
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Set("Content-Type", "application/json")
	if err := x.makeAuthenticatedRequestForJSON(id, req, &ms); err != nil {
		return nil, fmt.Errorf("Failed to fetch user profile (%v): %w", id, err)
	}

	email := ms.Mail
	if email == "" {
		email = ms.UserPrincipalName
	}

	prof := OAuthUserProfile{
		FirstName:   ms.GivenName,
		LastName:    ms.Surname,
		DisplayName: ms.DisplayName,
		Email:       email,
		UUID:        ms.ID,
	}

	return &prof, nil
}

// Perform an HTTP request, using the token associated with the given ID to authenticate the request.
// If the session token needs to be refreshed, then this function will automatically refresh
// the token.
func (x *OAuthProvider) makeAuthenticatedRequest(id string, r *http.Request) (*http.Response, error) {
	token, err := x.getOrRefreshToken(id)
	if err != nil {
		x.parent.Log.Infof("Failed to refresh OAuth token %v: %v", id[:6], err)

		// In any failure case, ensure that this record no longer exists in the DB.
		// If there are cases that can be retried then that retry logic should be
		// built into getOrRefreshToken()
		if _, err := x.parent.DB.Exec("DELETE FROM oauthsession WHERE id = $1", id); err != nil {
			x.parent.Log.Errorf("Failed to delete OAuth session for %v, after failed token refresh: %v", id[:6], err)
		}

		// In addition, work around any bugs that we may have in this code, where we forgot to
		// release locks on this token.
		x.tokenLock.Lock()
		delete(x.tokenInUse, id)
		delete(x.tokenRefresh, id)
		x.tokenLock.Unlock()

		return nil, err
	}
	defer func() {
		// Release our usage counter, so that if necessary, another thread can refresh the token
		x.tokenLock.Lock()
		if _, ok := x.tokenInUse[id]; !ok {
			// The fact that this token is no longer in the tokenInUse block, tells us that this
			// token has been destroyed by the above error-handling code block.
		} else {
			x.tokenInUse[id]--
			if x.tokenInUse[id] < 0 {
				// The above check to see if 'id' is present in the map, should catch any legitimate
				// conditions. So if the value really is less than zero, we have a bug.
				x.parent.Log.Errorf("tokenInUse[%v] less than zero", id[:6])
			}
			if x.tokenInUse[id] <= 0 {
				delete(x.tokenInUse, id)
			}
		}
		x.tokenLock.Unlock()
	}()
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := http.DefaultClient.Do(r)
	return resp, err
}

// Wrap makeAuthenticatedRequest, and unmarshal the response into JSON
func (x *OAuthProvider) makeAuthenticatedRequestForJSON(id string, r *http.Request, responseObj interface{}) error {
	resp, err := x.makeAuthenticatedRequest(id, r)
	if err != nil {
		return fmt.Errorf("Failed to execute authenticated request: %w", err)
	}
	respBody := []byte{}
	if resp.Body != nil {
		respBody, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("Failed to read body of authenticated request: %w", err)
		}
	}
	if err := json.Unmarshal(respBody, responseObj); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON of response body: %w", err)
	}
	return nil
}
