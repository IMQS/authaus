package authaus

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type MSAADProvider struct {
	parent MSAADInterface
	log    *log.Logger
	// Bearer token for communicating with Microsoft Graph API
	tokenLock      sync.Mutex
	token          string
	tokenExpiresAt time.Time
}

type msaadBearerTokenJSON struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type msaadUsersJSON struct {
	NextLink string           `json:"@odata.nextLink"`
	Value    []*msaadUserJSON `json:"value"`
}

/*
Example:

	{
		"businessPhones": [],
		"displayName": "Name Surname",
		"givenName": "Name",
		"jobTitle": null,
		"mail": "Name.surname@capetown.gov.za",
		"mobilePhone": null,
		"officeLocation": null,
		"preferredLanguage": null,
		"surname": "Surname",
		"userPrincipalName": "another@email.address",
		"id": "5c712197-beef-deef-ffff-f11bb800f365"
	}
*/
type msaadUserJSON struct {
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Mail              string `json:"mail"`
	Surname           string `json:"surname"`
	MobilePhone       string `json:"mobilePhone"`
	UserPrincipalName string `json:"userPrincipalName"`
	ID                string `json:"id"`
}

type msaadUser struct {
	profile msaadUserJSON
	roles   []*msaadRoleJSON
}

type msaadRolesJSON struct {
	NextLink string           `json:"@odata.nextLink"`
	Value    []*msaadRoleJSON `json:"value"`
}

type msaadRoleJSON struct {
	ID                   string `json:"id"`
	CreatedDateTime      string `json:"createdDateTime"`
	PrincipalDisplayName string `json:"principalDisplayName"`
	PrincipalID          string `json:"principalId"`
	PrincipalType        string `json:"principalType"`
	ResourceDisplayName  string `json:"resourceDisplayName"`
}

// Example of a single role:
//
//	{
//		"id": "qo0xrCYXk0yY8SkamzjdzeSmfTjLkNFCg9Wo9c89En4",
//		"deletedDateTime": null,
//		"appRoleId": "00000000-0000-0000-0000-000000000000",
//		"createdDateTime": "2020-07-28T12:57:43.8275923Z",
//		"principalDisplayName": "APP_USERS_IMQS",
//		"principalId": "ac318daa-1726-4c93-98f1-291a9b38ddcd",
//		"principalType": "Group",
//		"resourceDisplayName": "IMQS",
//		"resourceId": "9ae60502-e943-46be-ad74-2a219412e93e"
//	},

func (mp *MSAADProvider) IsShuttingDown() bool {
	return mp.parent.IsShuttingDown()
}

func (mp *MSAADProvider) Initialize(parent MSAADInterface, log *log.Logger) error {
	if parent == nil {
		return fmt.Errorf("MSAADProvider.Initialize: parent is nil")
	}
	mp.parent = parent
	if log == nil {
		return fmt.Errorf("MSAADProvider.Initialize: log is nil")
	}
	mp.log = log
	mp.tokenExpiresAt = time.Now().Add(-time.Hour)
	return nil
}

func (mp *MSAADProvider) Parent() MSAADInterface {
	return mp.parent
}

func (mp *MSAADProvider) GetUserAssignments(user *msaadUser, i int) (errGlobal error, quit bool) {
	//var errGlobal error
	selectURL := "https://graph.microsoft.com/v1.0/users/" + user.profile.ID + "/appRoleAssignments"
	for selectURL != "" {
		if errGlobal != nil {
			mp.log.Errorf("(%d) Global error detected in threadGroup-user-next loop...\n", i)
			break
		}
		if mp.IsShuttingDown() {
			break
		}
		j := msaadRolesJSON{}
		err := mp.fetchJSON(selectURL, &j)
		if err != nil {
			errGlobal = err
			return errGlobal, true
		}
		if mp.parent.Config().Verbose {
			mp.log.Infof("User %v (%v): %v\n", user.profile.bestEmail(), user.profile.ID, j)
			for _, u := range j.Value {
				mp.log.Infof("%v MSAAD User Permission: (%v)", user.profile.bestEmail(), u)
			}
		}
		user.roles = append(user.roles, j.Value...)
		selectURL = j.NextLink
	}
	return errGlobal, false
}

func (mp *MSAADProvider) GetAppRoles() (rolesList []string, errGlobal error, quit bool) {
	selectURL := "https://graph.microsoft.com/v1.0/servicePrincipals(appId='" + mp.parent.Config().ClientID + "')/appRoleAssignedTo"
	for selectURL != "" {
		if mp.IsShuttingDown() {
			break
		}
		j := msaadRolesJSON{}
		err := mp.fetchJSON(selectURL, &j)
		if err != nil {
			errGlobal = err
			return rolesList, errGlobal, true
		}
		for _, v := range j.Value {
			rolesList = append(rolesList, v.PrincipalDisplayName)
		}
		selectURL = j.NextLink
	}
	return rolesList, errGlobal, false
}

func (mp *MSAADProvider) GetAADUsers() ([]*msaadUser, error) {
	selectURL := "https://graph.microsoft.com/v1.0/users?$select=id,displayName,givenName,surname,mobilePhone,userPrincipalName,mail"
	aadUsers := []*msaadUser{}
	for selectURL != "" {
		if mp.parent.Config().Verbose {
			mp.log.Infof("Fetching %v\n", selectURL)
		}
		j := msaadUsersJSON{}
		if err := mp.fetchJSON(selectURL, &j); err != nil {
			return nil, err
		}
		for _, v := range j.Value {
			aadUsers = append(aadUsers, &msaadUser{
				profile: *v,
			})
		}
		selectURL = j.NextLink
	}
	return aadUsers, nil
}

func (mp *MSAADProvider) fetchJSON(fetchURL string, jsonRoot interface{}) error {
	request, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating Request object for url '%v': %v", fetchURL, err)
	}
	_, body, err := mp.doLoggedHTTP(request)
	if err != nil {
		return fmt.Errorf("Error fetching '%v' (err): %w", fetchURL, err)
	}
	return json.Unmarshal(body, jsonRoot)
}

// Execute doHTTP, and log any failure
// In addition, this function reads the response body, and returns
func (mp *MSAADProvider) doLoggedHTTP(request *http.Request) (*http.Response, []byte, error) {
	response, err := mp.doHTTP(request)
	if err != nil {
		e := fmt.Errorf("MSAAD failed to %v %v (err): %w", request.Method, request.URL.String(), err)
		mp.log.Error(e.Error())
		return nil, nil, e
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		e := fmt.Errorf("MSAAD failed to read response body from %v %v: %w", request.Method, request.URL.String(), err)
		mp.log.Error(e.Error())
		return nil, nil, e
	}

	if response.StatusCode != 200 {
		e := fmt.Errorf("MSAAD failed to %v %v (response): %v %v", request.Method, request.URL.String(), response.Status, string(body))
		mp.log.Error(e.Error())
		return nil, nil, e
	}

	return response, body, nil
}

func (mp *MSAADProvider) doHTTP(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "graph.microsoft.com" {
		// This is a safeguard to ensure that you don't accidentally send your bearer token to the wrong site
		return nil, fmt.Errorf("Invalid hostname request to MSAAD.DoHTTP '%v://%v'. Must be 'https://graph.microsoft.com'", request.URL.Scheme, request.URL.Host)
	}

	mp.tokenLock.Lock()
	if mp.tokenExpiresAt.Before(time.Now()) {
		newToken, newExpiry, err := mp.getBearerToken()
		if err != nil {
			mp.tokenLock.Unlock()
			return nil, err
		}
		mp.token = newToken
		mp.tokenExpiresAt = newExpiry
	}
	token := mp.token
	mp.tokenLock.Unlock()

	request.Header.Set("Authorization", "Bearer "+token)

	client := http.DefaultClient
	client.Timeout = 10 * time.Second
	return client.Do(request)
}

func (mp *MSAADProvider) getBearerToken() (token string, expiresAt time.Time, err error) {
	if mp.parent.Config().Verbose {
		mp.log.Infof("MSAAD refreshing bearer token")
	}
	tokenURL := "https://login.microsoftonline.com/" + mp.parent.Config().TenantID + "/oauth2/v2.0/token"

	params := map[string]string{
		"client_id":     mp.parent.Config().ClientID,
		"scope":         "https://graph.microsoft.com/.default",
		"client_secret": url.QueryEscape(mp.parent.Config().ClientSecret),
		"grant_type":    "client_credentials",
	}
	client := http.DefaultClient
	client.Timeout = 10 * time.Second
	resp, err := client.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(buildPOSTBodyForm(params)))
	if err != nil {
		err = fmt.Errorf("Error acquiring MSAAD bearer token: %w", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("Error reading MSAAD bearer token body: %w", err)
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("Error fetching MSAAD bearer token: %v", resp.Status)
		return
	}

	tokenJSON := msaadBearerTokenJSON{}
	if err = json.Unmarshal(body, &tokenJSON); err != nil {
		err = fmt.Errorf("Error unmarshalling MSAAD access token JSON ('%v'): %w", string(body), err)
		return
	}

	if tokenJSON.TokenType != "Bearer" {
		err = fmt.Errorf("Unexpected MSAAD token type '%v' (expected 'Bearer')", tokenJSON.TokenType)
		return
	}

	token = tokenJSON.AccessToken
	expiresAt = time.Now().Add(time.Duration(tokenJSON.ExpiresIn) * time.Second)

	if mp.parent.Config().Verbose {
		mp.log.Infof("MSAAD bearer token refreshed successfully: '%v'. ExpiresAt: %v", token[:4], expiresAt)
	}

	return
}

// nameAndSurname attempts to extract the name and surname from the DisplayName.
//
// If _both_ GivenName and Surname are populated, then we use those.
//
// If not, we attempt to split the DisplayName into a name and surname.
func (u *msaadUserJSON) nameAndSurname() (string, string) {
	if u.GivenName != "" && u.Surname != "" {
		return u.GivenName, u.Surname
	}
	return splitDisplayName(u.DisplayName)
}

// Split displayname into firstname, surname
//
// "Nick de Jager" -> "Nick" "de Jager"
//
// "Abraham Lincoln" -> "Abraham" "Lincoln"
//
// "Bad boy Bubby" -> "Bad" "boy Bubby" (this one is wrong, but there's just no way we can tell from a concatenated string)
func splitDisplayName(dn string) (string, string) {
	firstSpace := strings.Index(dn, " ")
	if firstSpace == -1 {
		return dn, ""
	}
	return dn[:firstSpace], dn[firstSpace+1:]
}

// bestEmail
// The main purpose of this function is to return a mail address, and NOT
// to provide a username per-se.
//
// If the mail field is populated, no problem and return it.
// If not, we can attempt to construct a mail address from the userPrincipalName,
// but only if the resulting string looks like an email address. If not,
// return blank.
//
// Methodology
// In the initial use case that we looked at, userPrincipalName was often auto-generated.
// The 'mail' field was clearly the desired email address of the person.
// However, the 'mail' field was missing from many entries, so in that case we fall back
// to userPrincipleEmail. We found the same thing with the LDAP synchronization (same client/tenant).
//
// The userPrincipalName is often in the format of an email address, but it is not guaranteed, so
// we need to validate that. In addition, for guest users, the
// userPrincipalName could also be a transformed concatenation of the home
// tenant UPN and the guest domain:
//
// homeTenantUPN#EXT#@guestDomain (with first homeTenantUPN's '@' replaced by '_')
//
// e.g.
//
// User's home tenant UPN: joan.soap@example.com
//
// Our domain: ourdomain.com
//
// Resulting guest UPN: joan.soap_example.com#EXT#ourdomain.com
//
// Since at this point we have no guarantee that the homeTenantUPN is in fact
// a valid email address, we try to parse it and if it looks like an email address
// we assume it is valid and return them - because it is our last resort.
func (u *msaadUserJSON) bestEmail() string {
	if u.Mail == "" {
		return convertUPNToEmail(u.UserPrincipalName)
	}
	return u.Mail
}

// convertUPNToEmail
// Primarily for Guest UPNs in Entra ID
// It MUST either: return a well-formed email address, OR a blank string.
//
// The function will:
// - test if the UPN contains '#EXT#'
// - if so, copy everything before that is first step
// - then convert all underscores to '@'
//
// The resulting string is then checked if it looks like a valid email address
// of the format name@domain. Where domain _must_ contain at least one '.'
// If considered valid, return it, otherwise return a blank string.
//
// Caveats
// Microsoft translates any disallowed characters in the home tenant UPN to '_',
// to it is possible to end up with a mail address with superflous '@'s. In which
// case it is unlikely to be correct, so we'll return a blank string in that case.
// Current list of special characters:
//
//		space character
//	`	accent grave
//	(	opening parenthesis
//	)	closing parenthesis
//	|	pipe
//	=	equal sign
//	?	question mark
//	/	forward slash
//	%	percent
func convertUPNToEmail(upn string) string {
	mailCandidate := upn
	if strings.Contains(upn, "#EXT#") {
		mailCandidate = strings.Split(upn, "#EXT#")[0]
		// res: joan.soap_example.com
		mailCandidate = strings.Replace(mailCandidate, "_", "@", -1)
		// res: joan.soap@example.com
	}

	parts := strings.Split(mailCandidate, "@")
	if len(parts) != 2 {
		return ""
	}

	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return ""
	}

	if !strings.Contains(parts[1], ".") {
		return ""
	}

	return mailCandidate
}

func (u *msaadUserJSON) toAuthUser() AuthUser {
	name, surname := u.nameAndSurname()
	email := u.bestEmail()
	return AuthUser{
		Type:         UserTypeMSAAD,
		Email:        email,
		Firstname:    name,
		Lastname:     surname,
		Mobilenumber: u.MobilePhone,
		ExternalUUID: u.ID,
		Username:     email,
	}
}

// Returns true if any fields have changed
func (u *msaadUserJSON) injectIntoAuthUser(target *AuthUser) bool {
	email := u.bestEmail()
	name, surname := u.nameAndSurname()
	changed := name != target.Firstname ||
		surname != target.Lastname ||
		u.MobilePhone != target.Mobilenumber ||
		target.Type != UserTypeMSAAD ||
		email != target.Email ||
		u.ID != target.ExternalUUID ||
		target.Username == ""
	// if changed {
	// 	fmt.Printf("A: %20v %20v %10v %v %v %v %v\n", name, surname, u.MobilePhone, UserTypeMSAAD, email, u.ID, u.UserPrincipalName)
	// 	fmt.Printf("B: %20v %20v %10v %v %v %v %v\n", target.Firstname, target.Lastname, target.Mobilenumber, target.Type, target.Email, target.ExternalUUID, target.Username)
	// }
	target.Firstname = name
	target.Lastname = surname
	target.Mobilenumber = u.MobilePhone
	target.Type = UserTypeMSAAD
	target.Email = email
	target.ExternalUUID = u.ID
	// We previously used UserPrincipalName here, but its format was cumbersome, so we
	// fall back to email.
	if target.Username == "" {
		target.Username = email
	}

	return changed
}
