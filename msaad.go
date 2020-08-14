package authaus

// This file contains functionality for reading the users from a Microsoft Azure Active Directory,
// via the Microsoft Graph API.
// See https://docs.microsoft.com/en-us/graph/use-the-api
// Once this is configured, the Authaus user database is periodically synchronized from
// the Azure Active Directory. This has the advantage that an administrator can setup
// a user's permissions before that user logs in for the first time.
//
// Sync Considerations
//
// It's relatively fast to ask Microsoft for the list of users in an AAD (a few seconds for
// a few hundred). However, fetching the roles that each user belongs to is much slower,
// because each fetch is a different HTTP request, and no matter what our bandwidth is,
// we pay a latency cost if we're going over the sea.
//
// To mitigate this cost, we parallize the fetching of the roles, and this has an almost
// linear speedup over fetching them serially.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigMSAAD is the JSON definition for the Microsoft Azure Active Directory synchronization settings
type ConfigMSAAD struct {
	Verbose              bool   // If true, then emit verbose logging
	DryRun               bool   // If true, don't actually take any action, just log the intended actions
	TenantID             string // Your tenant UUID (ie ID of your AAD instance)
	ClientID             string // Your client UUID (ie ID of your application)
	ClientSecret         string
	MergeIntervalSeconds int               // If non-zero, then overrides the merge interval
	EssentialRoles       []string          // List of principleName of AAD roles. If this list is not empty, then the user must belong to at least one of these groups, in order to be created in the Authaus DB
	RoleToGroup          map[string]string // Map from principleName of AAD role, to Authaus group.
	AllowArchiveUser     bool              // If true, then archive users who no longer have the relevant roles in the AAD
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

/* Example:
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

func (u *msaadUserJSON) nameAndSurname() (string, string) {
	if u.GivenName != "" && u.Surname != "" {
		return u.GivenName, u.Surname
	}
	return splitDisplayName(u.DisplayName)
}

func (u *msaadUserJSON) bestEmail() string {
	// In the initial use case that we looked at, userPrincipleEmail was often auto-generated.
	// The 'mail' field was clearly the desired email address of the person.
	// However, the 'mail' field was missing from many entries, so in that case we fall back
	// to userPrincipleEmail. We found the same thing with the LDAP synchronization (same client/tenant).
	if u.Mail == "" && strings.Index(u.UserPrincipalName, "@") != -1 {
		return u.UserPrincipalName
	}
	return u.Mail
}

func (u *msaadUserJSON) toAuthUser() AuthUser {
	name, surname := u.nameAndSurname()
	au := AuthUser{
		Type:         UserTypeMSAAD,
		Email:        u.bestEmail(),
		Firstname:    name,
		Lastname:     surname,
		Mobilenumber: u.MobilePhone,
		ExternalUUID: u.ID,
	}
	return au
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
		u.ID != target.ExternalUUID
	// if changed {
	// 	fmt.Printf("A: %20v %20v %10v %v %v %v\n", name, surname, u.MobilePhone, UserTypeMSAAD, email, u.ID)
	// 	fmt.Printf("B: %20v %20v %10v %v %v %v\n", target.Firstname, target.Lastname, target.Mobilenumber, target.Type, target.Email, target.ExternalUUID)
	// }
	target.Firstname = name
	target.Lastname = surname
	target.Mobilenumber = u.MobilePhone
	target.Type = UserTypeMSAAD
	target.Email = email
	target.ExternalUUID = u.ID
	return changed
}

type msaadUser struct {
	profile msaadUserJSON
	roles   []*msaadRoleJSON
}

func (u *msaadUser) hasRoleByPrincipleDisplayName(principleDisplayName string) bool {
	for _, r := range u.roles {
		if r.PrincipalDisplayName == principleDisplayName {
			return true
		}
	}
	return false
}

type msaadRolesJSON struct {
	NextLink string           `json:"@odata.nextLink"`
	Value    []*msaadRoleJSON `json:"value"`
}

// Example of a single role:
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
type msaadRoleJSON struct {
	ID                   string `json:"id"`
	CreatedDateTime      string `json:"createdDateTime"`
	PrincipalDisplayName string `json:"principalDisplayName"`
	PrincipalID          string `json:"principalId"`
	PrincipalType        string `json:"principalType"`
	ResourceDisplayName  string `json:"resourceDisplayName"`
}

// cachedRoleGroups is a cache of all the internal groups, as well as tables that allow us to
// access them quickly by ID and by Name
type cachedRoleGroups struct {
	groups      []*AuthGroup
	nameToGroup map[string]*AuthGroup
	idToGroup   map[GroupIDU32]*AuthGroup
}

// MSAAD is a container for the Microsoft Azure Active Directory synchronization system
type MSAAD struct {
	Config ConfigMSAAD

	parent *Central

	// Bearer token for communicating with Microsoft Graph API
	tokenLock      sync.Mutex
	token          string
	tokenExpiresAt time.Time

	numAADRoleFetches int
}

// Split displayname into firstname, surname
// "Nick de Jager" -> "Nick" "de Jager"
// "Abraham Lincoln" -> "Abraham" "Lincoln"
// "Bad boy Bubby" -> "Bad" "boy Bubby" (this one is wrong, but there's just no way we can tell from a concatenated string)
func splitDisplayName(dn string) (string, string) {
	firstSpace := strings.Index(dn, " ")
	if firstSpace == -1 {
		return dn, ""
	}
	return dn[:firstSpace], dn[firstSpace+1:]
}

func (m *MSAAD) Initialize(parent *Central) {
	m.parent = parent
	m.tokenExpiresAt = time.Now().Add(-time.Hour)
}

func (m *MSAAD) SynchronizeUsers() error {
	cachedRoleGroups, err := m.buildCachedRoleGroups()
	if err != nil {
		return err
	}

	// Log errors about missing internal group names (this is a config mistake)
	// We do this check once during sync, to avoid emitting this error during the sync of every user.
	for aadRole, internalGroupName := range m.Config.RoleToGroup {
		if _, ok := cachedRoleGroups.nameToGroup[internalGroupName]; !ok {
			m.parent.Log.Errorf("MSAAD internal group %v not recognized (for sync from %v)", internalGroupName, aadRole)
		}
	}

	// Fetch users
	aadUsers, err := m.getAADUsers()
	if err != nil {
		return err
	}

	// Augment AAD user data with AAD roles
	if len(m.Config.RoleToGroup) != 0 || len(m.Config.EssentialRoles) != 0 {
		err = m.getAADRoles(aadUsers)
		if err != nil {
			return err
		}
	}

	// Merge users into Authaus database
	existing, err := m.parent.userStore.GetIdentities(GetIdentitiesFlagNone)
	if err != nil {
		return err
	}
	emailToExisting := map[string]int{}
	uuidToExisting := map[string]int{}
	for i, u := range existing {
		emailToExisting[CanonicalizeIdentity(u.Email)] = i
		if u.ExternalUUID != "" {
			uuidToExisting[u.ExternalUUID] = i
		}
	}

	for _, aadUser := range aadUsers {
		aadEmail := aadUser.profile.bestEmail()
		if aadEmail == "" {
			continue
		}
		aadEmail = CanonicalizeIdentity(aadEmail)
		// First attempt: UUID
		ix, foundExisting := uuidToExisting[aadUser.profile.ID]
		if !foundExisting {
			// Second attempt: email
			ix, foundExisting = emailToExisting[aadEmail]
		}
		internalUserID := UserId(0)
		if foundExisting {
			// check if user needs to be updated
			internalUserID = existing[ix].UserId
			if aadUser.profile.injectIntoAuthUser(&existing[ix]) {
				if m.Config.DryRun {
					m.parent.Log.Infof("MSAAD dry-run: Update user %v %v %v", aadUser.profile.DisplayName, aadEmail, aadUser.profile.ID)
				} else {
					m.parent.Log.Infof("MSAAD update user %v %v %v", aadUser.profile.DisplayName, aadEmail, aadUser.profile.ID)
					existing[ix].Modified = time.Now()
					if err := m.parent.userStore.UpdateIdentity(&existing[ix]); err != nil {
						m.parent.Log.Warnf("MSAAD: Update user %v failed: %v", aadUser.profile.ID, err)
					}
				}
			}
		} else if m.userBelongsHere(aadUser) {
			// user does not exist, so create it
			if m.Config.DryRun {
				m.parent.Log.Infof("MSAAD dry-run: Create new user %v %v", aadUser.profile.DisplayName, aadEmail)
			} else {
				// actually create the user
				m.parent.Log.Infof("MSAAD create user %v %v", aadUser.profile.DisplayName, aadEmail)
				user := aadUser.profile.toAuthUser()
				user.Created = time.Now()
				user.Modified = user.Created
				if newUserID, err := m.parent.userStore.CreateIdentity(&user, ""); err != nil {
					m.parent.Log.Warnf("MSAAD: Create identity %v failed: %v", aadEmail, err)
				} else {
					internalUserID = newUserID
				}

				if m.parent.Auditor != nil {
					contextData := userInfoToAuditTrailJSON(user, "")
					m.parent.Auditor.AuditUserAction(user.Username, "User Profile: "+user.Username, contextData, AuditActionCreated)
				}
			}
		}

		if internalUserID != UserId(0) {
			// update groups of user
			if err := m.syncRoles(cachedRoleGroups, aadUser, internalUserID); err != nil {
				m.parent.Log.Errorf("MSAAD failed to synchronize roles for user %v: %v", aadUser.profile.DisplayName, err)
			}
		}
	}

	// Remove Authaus users that no longer exist in the AAD
	if m.Config.AllowArchiveUser {
		idToAAD := map[string]int{}
		for i, aadUser := range aadUsers {
			if m.userBelongsHere(aadUser) {
				idToAAD[aadUser.profile.ID] = i
			}
		}
		for _, user := range existing {
			if user.Type != UserTypeMSAAD {
				continue
			}
			_, insideAAD := idToAAD[user.ExternalUUID]
			if !insideAAD {
				if m.Config.DryRun {
					m.parent.Log.Infof("MSAAD dry-run: delete user %v %v", user.ExternalUUID, user.Email)
				} else {
					m.parent.Log.Infof("MSAAD Archive user %v %v", user.ExternalUUID, user.Email)
					if err := m.parent.userStore.ArchiveIdentity(user.UserId); err != nil {
						m.parent.Log.Errorf("MSAAD Archive of %v failed: %v", user.ExternalUUID, err)
					} else {
						if m.parent.Auditor != nil {
							contextData := userInfoToAuditTrailJSON(user, "")
							m.parent.Auditor.AuditUserAction(user.Username, "User Profile: "+user.Username, contextData, AuditActionDeleted)
						}
					}
				}
			}
		}
	}

	return nil
}

// Returns true if either Config.EssentialRoles is empty, or if the user belongs to one of the essential roles
func (m *MSAAD) userBelongsHere(user *msaadUser) bool {
	if len(m.Config.EssentialRoles) == 0 {
		return true
	}
	for _, essential := range m.Config.EssentialRoles {
		if user.hasRoleByPrincipleDisplayName(essential) {
			return true
		}
	}
	return false
}

func (m *MSAAD) buildCachedRoleGroups() (*cachedRoleGroups, error) {
	cache := &cachedRoleGroups{
		idToGroup:   map[GroupIDU32]*AuthGroup{},
		nameToGroup: map[string]*AuthGroup{},
	}
	groups, err := m.parent.GetRoleGroupDB().GetGroups()
	if err != nil {
		return nil, err
	}
	cache.groups = groups
	for _, g := range groups {
		cache.idToGroup[g.ID] = g
		cache.nameToGroup[g.Name] = g
	}
	return cache, nil
}

func indexInGroupInList(list []GroupIDU32, g GroupIDU32) int {
	for i, x := range list {
		if x == g {
			return i
		}
	}
	return -1
}

func removeFromGroupList(list []GroupIDU32, i int) []GroupIDU32 {
	// since order of groups is not important, we can just swap in the last element, then pop
	// off the final element from the slice, which is much faster than creating a new slice every time.
	list[i] = list[len(list)-1]
	return list[:len(list)-1]
}

func (m *MSAAD) syncRoles(roleGroups *cachedRoleGroups, aadUser *msaadUser, internalUserID UserId) error {
	nameInLogs := aadUser.profile.bestEmail()
	permit, err := m.parent.GetPermit(internalUserID)
	if err != nil && err != ErrIdentityPermitNotFound {
		m.parent.Log.Errorf("MSAAD failed to fetch permit for user %v: %v", nameInLogs, err)
		return err
	}
	if permit == nil {
		permit = &Permit{}
	}

	// Figure out the existing groups that this user belongs to
	groupIDs, err := DecodePermit(permit.Roles)
	if err != nil {
		return err
	}

	groupsChanged := false

	for aadRole, internalGroupName := range m.Config.RoleToGroup {
		internalGroup, ok := roleGroups.nameToGroup[internalGroupName]
		if !ok {
			// We've already logged an error about this, so here we just ignore it
			continue
		}

		logPrefix := "MSAAD"
		if m.Config.DryRun {
			logPrefix = "MSAAD dry-run:"
		}
		if aadUser.hasRoleByPrincipleDisplayName(aadRole) {
			// ensure that the user belongs to 'internalGroup'
			if indexInGroupInList(groupIDs, internalGroup.ID) == -1 {
				m.parent.Log.Infof(logPrefix+" grant %v to %v (from AAD role %v)", internalGroupName, nameInLogs, aadRole)
				if !m.Config.DryRun {
					groupsChanged = true
					groupIDs = append(groupIDs, internalGroup.ID)
				}
			}
		} else {
			// ensure that the user does not belong to 'internalGroup'
			idx := indexInGroupInList(groupIDs, internalGroup.ID)
			if idx != -1 {
				m.parent.Log.Infof(logPrefix+" remove %v from %v (lacking AAD role %v)", internalGroupName, nameInLogs, aadRole)
				if !m.Config.DryRun {
					groupsChanged = true
					groupIDs = removeFromGroupList(groupIDs, idx)
				}
			}
		}
	}

	if groupsChanged && !m.Config.DryRun {
		permit.Roles = EncodePermit(groupIDs)
		if err := m.parent.SetPermit(internalUserID, permit); err != nil {
			m.parent.Log.Errorf("MSAAD failed to set permit for user %v: %v", nameInLogs, err)
			return err
		}
	}

	return nil
}

func (m *MSAAD) getAADUsers() ([]*msaadUser, error) {
	selectURL := "https://graph.microsoft.com/v1.0/users?$select=id,displayName,givenName,surname,mobilePhone,userPrincipalName,mail"
	aadUsers := []*msaadUser{}
	for selectURL != "" {
		// m.parent.Log.Infof("Fetching %v", selectURL)
		j := msaadUsersJSON{}
		if err := m.fetchJSON(selectURL, &j); err != nil {
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

func numParallelFetchThreads(nItems int) int {
	nThreads := nItems / 10
	if nThreads < 1 {
		nThreads = 1
	}
	if nThreads > 8 {
		nThreads = 8
	}
	return nThreads
}

// Fetch user roles.
func (m *MSAAD) getAADRoles(users []*msaadUser) error {
	nThreads := numParallelFetchThreads(len(users))
	// partition 'users' into nThreads groups
	threadGroups := make([][]*msaadUser, nThreads)
	for i, u := range users {
		t := i % nThreads
		threadGroups[t] = append(threadGroups[t], u)
	}
	wg := sync.WaitGroup{}
	errChan := make(chan error, nThreads)

	startTime := time.Now()
	for _, threadGroupOuter := range threadGroups {
		wg.Add(1)
		go func(threadGroup []*msaadUser) {
			for _, user := range threadGroup {
				// Each of these calls is 0.2 seconds from my home network (South Africa to USA, presumably)... which is to be expected.
				// But that is the reason why we go to all this trouble to parallelize these fetches. If there are going to be, say, 10000
				// users on this AAD, then it certainly pays to parallelize these fetches.
				selectURL := "https://graph.microsoft.com/v1.0/users/" + user.profile.ID + "/appRoleAssignments"
				for selectURL != "" {
					if atomic.LoadUint32(&m.parent.shuttingDown) != 0 {
						break
					}
					j := msaadRolesJSON{}
					if err := m.fetchJSON(selectURL, &j); err != nil {
						errChan <- err
						break
					}
					// fmt.Printf("User %v (%v): %v\n", user.profile.bestEmail(), user.profile.ID, j)
					user.roles = append(user.roles, j.Value...)
					selectURL = j.NextLink
				}
			}
			wg.Done()
		}(threadGroupOuter)
	}

	wg.Wait()
	var err error
	if len(errChan) != 0 {
		err = <-errChan
	}

	seconds := time.Now().Sub(startTime).Seconds()
	if len(users) != 0 {
		if m.numAADRoleFetches < 3 || m.numAADRoleFetches%20 == 0 || m.Config.Verbose {
			m.parent.Log.Infof("Fetched %v AAD roles in %v seconds (%.2f seconds per fetch) (%v threads)", len(users), seconds, seconds*float64(nThreads)/float64(len(users)), nThreads)
		}
		m.numAADRoleFetches++
	}
	return err
}

func (m *MSAAD) fetchJSON(fetchURL string, jsonRoot interface{}) error {
	request, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating Request object for url '%v': %v", fetchURL, err)
	}
	response, body, err := m.doLoggedHTTP(request)
	if err != nil {
		return fmt.Errorf("Error fetching '%v' (err): %w", fetchURL, err)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Error fetching '%v' (response): %v", fetchURL, response.Status)
	}
	// if strings.Index(fetchURL, "appRole") != -1 && len(body) > 180 {
	// 	fmt.Printf("Body: %v\n", string(body))
	// }
	return json.Unmarshal(body, jsonRoot)
}

// Execute doHTTP, and log any failure
// In addition, this function reads the response body, and returns
func (m *MSAAD) doLoggedHTTP(request *http.Request) (*http.Response, []byte, error) {
	response, err := m.doHTTP(request)
	var responseBody []byte
	if err == nil && response.Body != nil {
		defer response.Body.Close()
		responseBody, err = ioutil.ReadAll(response.Body)
		if err != nil {
			m.parent.Log.Errorf("MSAAD failed to read response body from %v %v: %v", request.Method, request.URL.String(), err)
			return response, nil, err
		}
	}
	if err != nil {
		m.parent.Log.Errorf("MSAAD failed to %v %v (err): %v", request.Method, request.URL.String(), err)
	} else if response.StatusCode != 200 {
		m.parent.Log.Errorf("MSAAD failed to %v %v (response): %v %v", request.Method, request.URL.String(), response.Status, string(responseBody))
	}
	return response, responseBody, err
}

// DoHTTP executes an authenticated HTTP request to the Microsoft Graph API
func (m *MSAAD) doHTTP(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "graph.microsoft.com" {
		// This is a safeguard to ensure that you don't accidentally send your bearer token to the wrong site
		return nil, fmt.Errorf("Invalid hostname request to MSAAD.DoHTTP '%v://%v'. Must be 'https://graph.microsoft.com'", request.URL.Scheme, request.URL.Host)
	}

	m.tokenLock.Lock()
	if m.tokenExpiresAt.Before(time.Now()) {
		newToken, newExpiry, err := m.getBearerToken()
		if err != nil {
			m.tokenLock.Unlock()
			return nil, err
		}
		m.token = newToken
		m.tokenExpiresAt = newExpiry
	}
	token := m.token
	m.tokenLock.Unlock()

	request.Header.Set("Authorization", "Bearer "+token)

	return http.DefaultClient.Do(request)
}

func (m *MSAAD) getBearerToken() (token string, expiresAt time.Time, err error) {
	if m.Config.Verbose {
		m.parent.Log.Infof("MSAAD refreshing bearer token")
	}
	tokenURL := "https://login.microsoftonline.com/" + m.Config.TenantID + "/oauth2/v2.0/token"

	params := map[string]string{
		"client_id":     m.Config.ClientID,
		"scope":         "https://graph.microsoft.com/.default",
		"client_secret": url.QueryEscape(m.Config.ClientSecret),
		"grant_type":    "client_credentials",
	}
	resp, err := http.DefaultClient.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(buildPOSTBodyForm(params)))
	if err != nil {
		err = fmt.Errorf("Error acquiring MSAAD bearer token: %w", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
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

	if m.Config.Verbose {
		m.parent.Log.Infof("MSAAD bearer token refreshed successfully: '%v'. ExpiresAt: %v", token[:4], expiresAt)
	}

	return
}
