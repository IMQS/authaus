package authaus

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IMQS/log"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OAuthProviderI interface {
	//getUserProfile(id string, provider *ConfigOAuthProvider) (*OAuthUserProfile, error)
	//makeAuthenticatedRequest(id string, r *http.Request) (*http.Response, error)
	//makeAuthenticatedRequestForJSON(id string, r *http.Request, responseObj interface{}) error
	setLogger(logger *log.Logger)
	entraRefreshHTTP(id string, provider *ConfigOAuthProvider, token oauthToken) (oauthToken, error)
	getAccessToken(provider *ConfigOAuthProvider, code, pkceVerifier string) (*oauthToken, error)
	bareHTTP(r *http.Request, token *oauthToken) (*http.Response, error)
}

type OAuthDBI interface {
	Initialize(logger *log.Logger)
	setLogger(logger *log.Logger)
	getToken(id string) (string, time.Time, *oauthToken, error)
	updateToken(utc time.Time, newToken *oauthToken, id string) error
	getSessions() ([]oauthSession, error)
	deleteSession(id string) error
	getOrphanAuthSessions() (sessions []string, err error)
	purgeUnusedOAuthSessions()
	purgeExpiredChallenges()
	insertChallenge(id string, providerName string, created time.Time, nonce string, pckeVerifier string) error
	getChallenge(id string) (provider, codeVerifier string, err error)
	upgradeChallengeToSession(id string, token *oauthToken) error
	getLastSession() (string, error)
}

const DefaultOAuthLoginExpirySeconds = 5 * 60
const DefaultOAuthTokenCheckIntervalSeconds = 5 * 60

const (
	OAuthProviderMSAAD = "msaad" // Microsoft Azure Active Directory
)

type ConfigOAuthProvider struct {
	Type            string // See OAuthProvider___ constants for legal values
	Title           string // Name of provider that user sees (probably need an image too)
	ClientID        string // For MSAAD
	LoginURL        string // eg https://login.microsoftonline.com/e1ff61b3-a3da-4639-ae31-c6dff3ce7bfb/oauth2/v2.0/authorize
	TokenURL        string // eg https://login.microsoftonline.com/e1ff61b3-a3da-4639-ae31-c6dff3ce7bfb/oauth2/v2.0/token
	RedirectURL     string // eg https://stellenbosch.imqs.co.za/auth2/oauth/finish. URL must be listed in IMQS app in Azure. Can be http://localhost/auth2/oauth/finish for testing.
	Scope           string
	ClientSecret    string
	AllowCreateUser bool // If true, then automatically create an Authaus user for an OAuth user, if the user succeeds in logging in
}

type ConfigOAuth struct {
	Providers                 map[string]*ConfigOAuthProvider
	Verbose                   bool   // If true, then print a lot of debugging information
	ForceFastTokenRefresh     bool   // If true, then force a token refresh every 120 seconds. This is for testing the token refresh code.
	LoginExpirySeconds        int64  // A session that starts must be completed within this time period (eg 5 minutes)
	TokenCheckIntervalSeconds int    // Override interval at which we check that OAuth tokens are still valid, and if not, invalidate the Authaus session. Set to -1 to disable this check.
	DefaultProvider           string // Can be set to the name of one of the Providers. This was created for the login JS front-end, to act as though the user has pressed the "Sign-in with XYZ" button as soon as the page is loaded.
}

type OAuthCompletedResult struct {
	Profile        *OAuthUserProfile // User profile that has been read from the OAuth server
	IsNewUser      bool              // True if this user has just been created
	UserId         UserId            // Non-zero if Success is true
	OAuthSessionID string
}

type oauthStartResponseJSON struct {
	LoginURL string
}

// OAuth This is just a container for OAuth functions and state, so that we don't
// pollute the 'Central' struct with all of our stuff.
type OAuth struct {
	Config ConfigOAuth

	parent        *Central
	OAuthProvider OAuthProviderI
	OAuthDB       OAuthDBI
	// In order to prevent races at refreshing an OAuth token, we use a hash map
	// to ensure that only one thread is trying to do that at a time. It IS POSSIBLE
	// to use the database for this purpose, but getting that right is much more
	// error-prone that a simple hash table and a mutex, so we do the simple thing.
	tokenLock    sync.Mutex      // Guards access to refreshMap
	tokenInUse   map[string]int  // Toggled to true while we're busy refreshing an OAuth token. Map key is ID of the session.
	tokenRefresh map[string]bool // Toggled to true while we're busy refreshing an OAuth token. Map key is ID of the session.
}

type oauthToken struct {
	AccessToken      string  `json:"access_token"`
	TokenType        string  `json:"token_type"`
	ExpiresIn        float64 `json:"expires_in"`
	Scope            string  `json:"scope"`
	RefreshToken     string  `json:"refresh_token"`
	IDToken          string  `json:"id_token,omitempty"`
	Error            string  `json:"error,omitempty"`
	ErrorDescription string  `json:"error_description,omitempty"`
}

func (t *oauthToken) toJSON() string {
	b, _ := json.Marshal(t)
	return string(b)
}

func minInt(a int, b int) int {
	if a > b {
		return b
	} else {
		return a
	}
}

type msaadUserProfile struct {
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Mail              string `json:"mail"`
	MobilePhone       string `json:"mobilePhone"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"`
	ID                string `json:"id"`
}

type OAuthUserProfile struct {
	DisplayName string
	FirstName   string
	LastName    string
	Email       string
	Phone       string
	UUID        string
}

func (c *ConfigOAuth) LoginExpiry() time.Duration {
	if c.LoginExpirySeconds == 0 {
		return DefaultOAuthLoginExpirySeconds * time.Second
	}
	return time.Duration(c.LoginExpirySeconds) * time.Second
}

func (x *OAuth) Initialize(parent *Central) {
	x.parent = parent
	x.tokenInUse = map[string]int{}
	x.tokenRefresh = map[string]bool{}
	x.OAuthProvider.setLogger(parent.Log)
	x.OAuthDB.Initialize(parent.Log)

	// Run a cleanup loop
	go func() {
		// Startup grace
		time.Sleep(5 * time.Second)
		for !x.parent.IsShuttingDown() {
			x.OAuthDB.purgeUnusedOAuthSessions()
			time.Sleep(time.Minute)
		}
	}()

	if x.Config.TokenCheckIntervalSeconds != -1 {
		// Run a loop that checks the validity of OAuth tokens, and if they're no longer valid,
		// then expire the Authaus session associated with it.
		go func() {
			interval := x.Config.TokenCheckIntervalSeconds
			if interval == 0 {
				interval = DefaultOAuthTokenCheckIntervalSeconds
			}
			// Startup grace
			time.Sleep(5 * time.Second)
			for !x.parent.IsShuttingDown() {
				x.validateTokens()
				time.Sleep(time.Duration(interval) * time.Second)
			}
		}()
	}
}

// HttpHandlerOAuthStart This is a GET or POST request that the frontend calls, in order to start an OAuth login sequence
func (x *OAuth) HttpHandlerOAuthStart(w http.ResponseWriter, r *http.Request) {
	// This is just some extremely crude rate limiting, but this is an interactive
	// flow that involves a bunch of user clicks, so I feel it's OK to impose it here.
	time.Sleep(50 * time.Millisecond)

	if r.Form == nil {
		HttpSendTxt(w, http.StatusBadRequest, "Invalid request, form is nil")
		return
	}

	providerName := r.FormValue("provider")
	provider := x.Config.Providers[providerName]
	if provider == nil {
		HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("OAuth provider '%v' not configured", providerName))
		return
	}

	// Create a session
	sessionID, nonce, pkceChallenge, err := x.createChallenge(providerName, provider, r)
	if err != nil {
		HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	// Tell the caller where to redirect the browser URL to
	loginURL, err := createOAuthURL(provider, sessionID, nonce, pkceChallenge, r)
	if err != nil {
		HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to create OAuth login URL: %v", err))
		return
	}

	if x.Config.Verbose {
		x.parent.Log.Infof("Created OAuth challenge sessionID:%v... nonce:%v... pkceChallenge:%v...", sessionID[:6], nonce[:6], pkceChallenge[:6])
	}

	if r.Method == "GET" {
		// Redirect to the OAuth provider's page
		http.Redirect(w, r, loginURL, http.StatusFound)
	} else {
		resp := oauthStartResponseJSON{
			LoginURL: loginURL,
		}
		HttpSendJSON(w, 200, &resp)
	}
}

// HttpHandlerOAuthFinish This is a dummy "finish" handler. A real handler would be a function where you create
// a session cookie, and then redirect the user to a reasonable landing page.
func (x *OAuth) HttpHandlerOAuthFinish(w http.ResponseWriter, r *http.Request) {
	res, err := x.OAuthFinish(r)
	if err != nil {
		HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}
	HttpSendTxt(w, http.StatusOK, fmt.Sprintf("OAuth login success, IsNewUser = %v, UserId = %v", res.IsNewUser, res.UserId))
}

// OAuthFinish handles the URL where the user gets redirected after completing a successful login to the OAuth provider.
// It is the OAuth provider's website that redirects the user back here. This is a GET request, and inside the
// URL, behind the fragment, are the login details.
// One major thing omitted from this function, is the creation of a session record, and returning a cookie
// to the browser. This is intentional, because it's very likely that you may want to do additional things,
// such as assigning some roles, before creating the session.
// If AllowCreateUser is false, and the user does not exist in the Authaus database, then this function
// does not return an error. However, the UserId field in OAuthCompletedResult will be zero, and it is
// your responsibility to deal with that however you choose (either create a user yourself, or halt the
// login process).
// Note that if you do not create an Authaus session within a few minutes, then the OAuth session will be
// cleared out by the cleaner thread, which deletes stale OAuth sessions, which have no link to an Authaus session.
func (x *OAuth) OAuthFinish(r *http.Request) (*OAuthCompletedResult, error) {
	// Example URL:
	// http://localhost/auth2/oauth/finish#
	//   code=OAQABAAIA...
	//  &state=login123
	//  &session_state=acdf42cb-ee38-4c9a-b6c5-7d03ec1d3906
	x.OAuthDB.purgeExpiredChallenges()

	id := r.FormValue("state")
	code := r.FormValue("code")

	providerName, pkceVerifier, err := x.OAuthDB.getChallenge(id)
	if err != nil {
		if x.Config.Verbose {
			x.parent.Log.Infof("OAuth failed to retrieve session '%v': %v", id[:6], err)
		}
		return nil, fmt.Errorf("Failed to retrieve session: %w", err)
	}
	provider := x.Config.Providers[providerName]
	if provider == nil {
		return nil, fmt.Errorf("Unknown OAuth provider '%v'", providerName)
	}
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far
	if provider.Type != OAuthProviderMSAAD {
		return nil, fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
	}
	token, err := x.OAuthProvider.getAccessToken(provider, code, pkceVerifier)
	if err != nil {
		return nil, fmt.Errorf("Failed to get access token: '%w'", err)
	}
	if err := x.OAuthDB.upgradeChallengeToSession(id, token); err != nil {
		return nil, fmt.Errorf("Failed to commit token to database: '%w'", err)
	}

	// Ask the OAuth server for the user details, so that we log the user into Authaus
	profile, err := x.getUserProfile(id, provider)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch user profile for id (%v): '%w'", id, err)
	}

	if x.Config.Verbose {
		x.parent.Log.Infof("Got OAuth user profile displayName:%v, email:%v, uuid:%v", profile.DisplayName, profile.Email, profile.UUID)
	}
	/*
		There are a couple of issues here that need to be resolved:
		1. !AllowCreateUser can log in a user that does not have an external uuid.
		In principle this is fine, since the user had provided the correct credentials,
		which should match what is retrieved from the provider and recorded in auth.

		However, the question becomes how permissions are managed. Two options:
		- (A) The user's permissions are managed in the service (by a user admin), or
		- (B) The user's permissions are managed by the provider via mapped security groups.
		This requires an external uuid (at least for MSAAD), because it happens
		in a thread which is not connected to the current session (user).

		One _could_ do the sync based on the email address, but that is not a good idea
		because that can change.

		The auth system assigns a user type to the user, which, in steady state,
		should indicate how a user's identity (and permissions are managed).

		However, we've implemented a "merge" or "upgrade" function in MSAAD so
		that a native user can be upgraded to a provider managed user.

		* PROBLEM STATEMENT *
		The main issue lies with the upgrade mechanism.
		For !AllowCreateUser, the user is not created, and the user is not upgraded.
		This means that even though the user login clearly depends on a provider,
		this never gets recorded and the user is never upgraded. This may prevent
		other logic pertaining to the provider from ever executing against the user.

		Use case. When both OAuth and MSAAD are configured, it is possible to
		have a native user in the database (no ext-UUID), as well as a MSAAD user
		with the native users' old email address.
		(1) When syncing, MSAAD finds the MSAAD user and updates permissions. It errors
			when trying to update the email address, because the native user exists.
		(2) When the user logs in, the OAuth redirect works, but the user is matched
		against the native user and thus permissions are not correct.

		The MSAAD sync does not identify the user correctly during the sync,
		because it first checks the ext-uuid.
		OAuth does not link the user to the correct UserId, because it searches
		on the new email address.

		Although somewhat artificial, we've seen this happen in practice, and it is
		difficult to troubleshoot and requires manual intervention to correct.

		In addition, the situation may be compounded by having allowcreateuser=true
		as well as MSAAD sync active.
	*/
	result := OAuthCompletedResult{
		OAuthSessionID: id,
		Profile:        profile,
	}
	found, userid, errArchiveMatch := x.parent.userStore.MatchArchivedUserExtUUID(profile.UUID)
	if errArchiveMatch != nil {
		return nil, fmt.Errorf("Could not check user status: '%w'", errArchiveMatch)
	}
	if found {
		result.UserId = userid
		return &result, fmt.Errorf("User exists, but is archived.")
	}

	if provider.AllowCreateUser {
		// If MSAAD is enabled for the provider, we should not allow users to be created
		// Also, we should modify createOrGetUserID to find the user by external UUID
		userId, err := x.createOrGetUserID(profile)
		if err == nil {
			result.IsNewUser = true
			result.UserId = userId
		} else if errors.Is(err, ErrIdentityExists) {
			// We've already checked for archived users, so this is a normal user
			// and we need
			result.IsNewUser = false
			result.UserId = userId
		} else if err != nil {
			return nil, fmt.Errorf("Failed to create internal user profile for '%v': '%w'", profile.DisplayName, err)
		}
	} else {
		// We have to prevent the user from logging in if
		// MSAAD is enabled and the found user does not have an external UUID.
		user, err := x.parent.GetUserFromIdentity(profile.Email)
		if err == nil {
			result.UserId = user.UserId
			// NB : It is not possible for the error checked below to be returned!!!
		} else if err == ErrIdentityAuthNotFound {
			// As documented for this function, we don't consider this an error, and the
			// caller is responsible for checking result.UserId
		} else {
			return nil, fmt.Errorf("Failed to fetch internal user profile for '%v': '%w'", profile.DisplayName, err)
		}
	}

	if x.Config.Verbose {
		x.parent.Log.Infof("OAuth authorization completed IsNewUser:%v, UserID:%v", result.IsNewUser, result.UserId)
	}

	return &result, nil
}

// HttpHandlerOAuthTest It's useful to keep a function like this around, so that you can iterate on this stuff without having
// to go through a complete login cycle every time. I'm afraid I'm going to burn up some max-logins-per-hour
// quota or something like that.
func (x *OAuth) HttpHandlerOAuthTest(w http.ResponseWriter, r *http.Request) {
	id, err := x.OAuthDB.getLastSession()
	if id == "" {
		HttpSendTxt(w, http.StatusOK, "No sessions")
		return
	}

	err = x.getMe(w, r, id)
	if err != nil {
		x.parent.Log.Warnf("Failed to getMe: %v", err)
	}
	//req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	//if err != nil {
	//	HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to build request: %v", err))
	//	return
	//}
	//req.Header.Set("Content-Type", "application/json")
	//resp, err := x.OAuthProvider.makeAuthenticatedRequest(id, req)
	//if err != nil {
	//	HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to execute authenticated request: %v", err))
	//	return
	//}
	//
	//// forward the response
	//for k, v := range resp.Header {
	//	for _, vv := range v {
	//		w.Header().Add(k, vv)
	//	}
	//}
	//w.WriteHeader(resp.StatusCode)
	//if resp.Body != nil {
	//	io.Copy(w, resp.Body)
	//	resp.Body.Close()
	//}
}

// OAuthLoginUsernamePassword
// Provides support for username and password login to MSAAD
// App to app authentication.
// This is NOT recommended for normal user access but for trusted applications that have their own user credentials in MSAAD
// AND is linked to the same tenant ID under which auth operates.
func (x *OAuth) OAuthLoginUsernamePassword(username string, password string) (error, string) {
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far

	/* TODO : We refer to the "provider" by name in the config (e.g. emerge), but in the database, we refer to it by
	type alone. In essence the store does not have any information on WHICH provider will be used to authenticate against,
	should there be more than one of the same type.
	*/

	var provider *ConfigOAuthProvider
	for _, p := range x.Config.Providers {
		if p.Type == OAuthProviderMSAAD {
			provider = p
		}
	}
	if provider == nil {
		return fmt.Errorf("OAuth provider '%v' not configured", OAuthProviderMSAAD), ""
	}

	//client_id:56ba925b-6912-4068-ac2c-d77997310431 (example)
	//scope:user.read openid profile
	//client_secret:
	//grant_type:password
	//username:john.von.neumann@mathsworld.com
	//password:

	params := map[string]string{
		"client_id":     provider.ClientID,
		"scope":         provider.Scope,
		"client_secret": url.QueryEscape(provider.ClientSecret),
		"grant_type":    "password",
		"username":      username,
		"password":      password,
	}

	// make the call to msaad
	resp, err := http.DefaultClient.Post(provider.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(buildPOSTBodyForm(params)))
	if err != nil {
		return fmt.Errorf("Error acquiring access token: %w", err), ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading access token body: %w", err), ""
	}

	token := oauthToken{}
	if err := json.Unmarshal(body, &token); err != nil {
		return fmt.Errorf("Error unmarshalling access token JSON: %w", err), ""
	}

	if token.Error != "" {
		return fmt.Errorf("Error acquiring access token: %v, %v", token.Error, token.ErrorDescription), ""
	}

	// at this point we know the user is valid
	if token.RefreshToken == "" {
		// This is not strictly an error - maybe some workflows are fine
		// with this, particularly if the expiry time is large.
		// However, I'm just being super conservative here.
		// Note also, that if the only purpose of OAuth is to authenticate
		// the person, and get their email/profile, then this error is
		// entirely bogus, and can be removed.
		// The offline_access scope is required for MSAAD to send a refresh_token.
		// I have no idea how general that principle is, with other OAuth providers.
		return fmt.Errorf("Access Token acquired, but it has no refresh_token. Perhaps you forgot to request the offline_access scope?"), ""
	}

	// create an oauthsession entry

	db := x.parent.DB
	tx, err := db.Begin()
	if err != nil {
		return err, ""
	}
	defer tx.Rollback()

	if x.Config.Verbose {
		x.parent.Log.Infof("Insert placeholder oauthsession for '%v'", username[:minInt(6, len(username))])
	}

	instantNow := time.Now().UTC()

	// this is NOT an auth session key, but a unique identifier for the oauth session entry
	key := generateSessionKey()
	_, err = tx.Exec("INSERT INTO oauthsession(id, provider, created, updated) VALUES ($1, $2, $3, $4)", key, provider.Title, instantNow, instantNow)
	if err != nil {
		return fmt.Errorf("Error inserting into oauthsession: %w", err), ""
	}
	_, err = tx.Exec("UPDATE oauthsession SET token = $1 WHERE id = $2", token.toJSON(), key)
	if err != nil {
		return fmt.Errorf("Error updating oauthsession with initial token: %w", err), ""
	}

	// the user does not have a session (and therefore no permit either), it is the caller's responsibility to create the session
	return tx.Commit(), key
}

func (x *OAuthProvider) getAccessToken(provider *ConfigOAuthProvider, code, pkceVerifier string) (*oauthToken, error) {
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far
	if provider.Type != OAuthProviderMSAAD {
		return nil, fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
	}

	params := map[string]string{
		"client_id":     provider.ClientID,
		"scope":         provider.Scope,
		"redirect_uri":  provider.RedirectURL,
		"client_secret": url.QueryEscape(provider.ClientSecret),
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": pkceVerifier,
	}

	// x.Log.Infof("GetAccessToken %v", params)

	resp, err := http.DefaultClient.Post(provider.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(buildPOSTBodyForm(params)))
	if err != nil {
		return nil, fmt.Errorf("Error acquiring access token: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading access token body: %w", err)
	}

	token := oauthToken{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("Error unmarshalling access token JSON: %w", err)
	}

	// x.Log.Infof("OAuth access token response: %v", string(body))

	if token.Error != "" {
		return nil, fmt.Errorf("Error acquiring access token: %v, %v", token.Error, token.ErrorDescription)
	}
	if token.RefreshToken == "" {
		// This is not strictly an error - maybe some workflows are fine
		// with this, particularly if the expiry time is large.
		// However, I'm just being super conservative here.
		// Note also, that if the only purpose of OAuth is to authenticate
		// the person, and get their email/profile, then this error is
		// entirely bogus, and can be removed.
		// The offline_access scope is required for MSAAD to send a refresh_token.
		// I have no idea how general that principle is, with other OAuth providers.
		return nil, fmt.Errorf("Access Token acquired, but it has no refresh_token. Perhaps you forgot to request the offline_access scope?")
	}

	return &token, nil
}

func (x *OAuth) createChallenge(providerName string, provider *ConfigOAuthProvider, r *http.Request) (id, nonce, pkceChallenge string, err error) {
	// The MS Azure Active Directory wants a nonce and a state variable, which from our point of view are both just
	// arbitrary nonces.
	id = generateRandomKey(30)
	nonce = generateRandomKey(30)
	pkceVerifier, pkceChallenge := createPKCE()

	x.OAuthDB.purgeExpiredChallenges()

	if x.Config.Verbose {
		x.parent.Log.Infof("Insert OAuth challenge %v", id[:6])
	}

	err = x.OAuthDB.insertChallenge(id, providerName, time.Now().UTC(), nonce, pkceVerifier)
	if err != nil {
		return
	}
	//if _, err = x.parent.DB.Exec("INSERT INTO oauthchallenge (id, provider, created, nonce, pkce_verifier) VALUES ($1, $2, $3, $4, $5)",
	//	id, providerName, time.Now().UTC(), nonce, pkceVerifier); err != nil {
	//	x.parent.Log.Errorf("Failed to insert OAuth challenge %v: %v", id[:6], err)
	//	return
	//}
	return
}

// If this function returns successfully, then tokenInUse[id] has been incremented,
// and needs to be decremented once you are done using it to make your API request.
func (x *OAuth) getOrRefreshToken(id string) (*oauthToken, error) {
	//db := x.parent.DB
	for sessionWait := 0; true; sessionWait++ {
		if sessionWait == 120 {
			return nil, fmt.Errorf("Timed out waiting for a session key in getOrRefreshToken(%v)", id[:6])
		}
		//updated      time.Time
		var token *oauthToken
		// Check to see if the session is valid
		providerName, updated, token, err2 := x.OAuthDB.getToken(id)
		//err := db.QueryRow("SELECT provider, updated, token FROM oauthsession WHERE id = $1", id).Scan(&providerName, &updated, &tokenStr)
		//if err != nil {
		//	return nil, sql.ErrNoRows
		//}
		//if err := json.Unmarshal([]byte(tokenStr), &token); err != nil {
		//	return nil, fmt.Errorf("Error unmarshalling token %v from database: %w", id[:6], err)
		//}
		if err2 != nil {
			return nil, err2
		}
		provider := x.Config.Providers[providerName]
		if provider == nil {
			return nil, fmt.Errorf("OAuth provider '%v', from token, is not configured", providerName)
		}
		// Microsoft Azure Active Directory is the only provider we've needed to implement so far
		if provider.Type != OAuthProviderMSAAD {
			return nil, fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
		}
		// Renew a token some time before it is due to expire.
		// MSAAD gives a 3599 seconds expiry, and Google is a little higher, so 60 seconds is a decent buffer,
		// and also should provide a reasonable amount of isolation against a slow network (ie we expect API calls
		// to the OAuth provider to authenticate in much less than 60 seconds)
		// Ideally, we should implement request cancellation inside makeAuthenticatedRequest(), where we
		// cancel requests long before 60 seconds elapses (eg after 30 seconds).
		renewBefore := 60 * time.Second

		expireTime := updated.Add(time.Duration(int(token.ExpiresIn)) * time.Second).Add(-renewBefore)

		// Does this work?.... To take the lock before reading the time?
		// I think so yes... what this interesting construct does, is it ensures that threads will resume post-lock,
		// in an order that is consistent with their view of time.Now(). In other words, it prevents the situation
		// where a thread goes down the "This token is expired" path, and then another thread, executing after it,
		// goes down the "This token is valid" path.
		x.tokenLock.Lock()
		isExpired := expireTime.Before(time.Now())
		if !isExpired {
			x.tokenInUse[id]++
			x.tokenLock.Unlock()
			return token, nil
		}
		// Try to acquire the refresh lock
		if x.tokenRefresh[id] {
			// Another thread is already attempting a refresh, so pause, then go back to the start
			x.tokenLock.Unlock()
			time.Sleep(time.Second)
			continue
		}
		if x.Config.Verbose {
			x.parent.Log.Infof("OAuth refreshing token id:%v...", id[:6])
		}

		// We have obtained the refresh lock
		// NOTE: Code below must ensure that x.tokenRefresh[id] is released.
		x.tokenRefresh[id] = true
		x.tokenLock.Unlock()

		// But we're not done yet - we need to wait until all of the existing users of this token are finished.
		// But what if the other threads never back off? They will back off, because they'll see, just like we did,
		// that this token is about to expire, and then they'll hit the above code path, where they see that we
		// have already acquired the refresh lock.
		for usageWait := 0; true; usageWait++ {
			if usageWait == 120 {
				x.tokenLock.Lock()
				delete(x.tokenRefresh, id)
				x.tokenLock.Unlock()
				return nil, fmt.Errorf("Timed out waiting for session key %v usage to drop to zero", id[:6])
			}
			x.tokenLock.Lock()
			usage := x.tokenInUse[id]
			x.tokenLock.Unlock()
			if usage == 0 {
				break
			}
			time.Sleep(time.Second)
		}

		// We make innerRefresh a standalone function so that we can reliably unlock tokenRefresh[id]
		if err := x.innerRefresh(id, provider, *token); err != nil {
			return nil, err
		}

		// We are done. On the next iteration of the loop, everything should succeed
		x.parent.Log.Infof("Refreshed OAuth token %v", id[:6])
	}
	// Unreachable code
	return nil, nil
}

// This function assumes that we are holding the tokenRefresh lock for the given id.
// We keep this part of the refresh a function on it's own, so that we can use a single "defer"
// statement to ensure that we remove our tokenRefresh lock when we're done, regardless
// of whether we succeed or fail.
func (x *OAuth) innerRefresh(id string, provider *ConfigOAuthProvider, token oauthToken) error {
	defer func() {
		x.tokenLock.Lock()
		delete(x.tokenRefresh, id)
		x.tokenLock.Unlock()
	}()

	newToken, err3 := x.OAuthProvider.entraRefreshHTTP(id, provider, token)
	if err3 != nil {
		return err3
	}

	err2 := x.OAuthDB.updateToken(time.Now().UTC(), &newToken, id)
	if err2 != nil {
		return err2
	}
	return nil
}

func (x *OAuthProvider) setLogger(logger *log.Logger) {
	x.Log = logger
}
func (x *OAuthProvider) entraRefreshHTTP(id string, provider *ConfigOAuthProvider, token oauthToken) (oauthToken, error) {
	// Refresh the token
	params := map[string]string{
		"client_id":     provider.ClientID,
		"scope":         provider.Scope,
		"refresh_token": token.RefreshToken,
		"client_secret": url.QueryEscape(provider.ClientSecret),
		"grant_type":    "refresh_token",
	}
	refresh, err := http.NewRequest("POST", provider.TokenURL, strings.NewReader(buildPOSTBodyForm(params)))
	if err != nil {
		return oauthToken{}, err
	}
	refresh.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(refresh)
	if err != nil {
		return oauthToken{}, fmt.Errorf("Error refreshing token %v (connection): %w", id[:6], err)
	}
	respBody := []byte{}
	if resp.Body != nil {
		respBody, _ = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if resp.StatusCode != 200 {
		return oauthToken{}, fmt.Errorf("Error refreshing token %v: %v, %v", id[:6], resp.Status, string(respBody))
	}

	// x.parent.Log.Infof("Refresh token body: %v", string(respBody))

	newToken := oauthToken{}
	if err := json.Unmarshal(respBody, &newToken); err != nil {
		return oauthToken{}, fmt.Errorf("Error unmarshalling refresh token %v response: %w", id[:6], err)
	}
	if newToken.Error != "" {
		return oauthToken{}, fmt.Errorf("Error acquiring refresh token %v: %v, %v", id[:6], newToken.Error, newToken.ErrorDescription)
	}

	if x.Config.ForceFastTokenRefresh {
		x.Log.Infof("After refresh, decreasing expiry time of refresh token from %v to %v, for testing", newToken.ExpiresIn, 120)
		newToken.ExpiresIn = 120
	}
	return newToken, nil
}

func (x *OAuthProvider) bareHTTP(r *http.Request, token *oauthToken) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := http.DefaultClient.Do(r)
	return resp, err
}

type oauthSession struct {
	id       string
	provider string
}

// This function is called periodically, to verify that the OAuth token is still valid.
// If the OAuth token is no longer valid, then the Authaus session is invalidated too.
// This functionality is optional.
func (x *OAuth) validateTokens() {
	if x.Config.Verbose {
		x.parent.Log.Infof("Validating OAuth tokens")
	}
	//sessions := []oauthSession{}
	sessions, err := x.OAuthDB.getSessions()
	if err != nil {
		x.parent.Log.Warnf("OAuth validateTokens failed to read oauthsession from DB: %v", err)
		return
	}
	//if rows, err := x.parent.DB.Query("SELECT id, provider FROM oauthsession"); err != nil {
	//	x.parent.Log.Warnf("OAuth validateTokens failed to read oauthsession from DB: %v", err)
	//	return
	//} else {
	//	defer rows.Close()
	//	for rows.Next() {
	//		id := ""
	//		provider := ""
	//		if err := rows.Scan(&id, &provider); err != nil {
	//			x.parent.Log.Warnf("OAuth validateTokens failed to scan oauthsession from DB: %v", err)
	//			return
	//		}
	//		sessions = append(sessions, oauthSession{
	//			id:       id,
	//			provider: provider,
	//		})
	//	}
	//}

	// Iterate over all sessions, and ping their provider, which forces their validity to be checked.
	for _, session := range sessions {
		prov := x.Config.Providers[session.provider]
		if prov == nil {
			// provider has been removed from config, so delete the session
			err := x.OAuthDB.deleteSession(session.id)
			if err != nil {
				x.parent.Log.Warnf("Error deleting from oauthsession table for unconfigured provider '%v': %v", session.provider, err)
			} else {
				x.parent.Log.Infof("Deleted oauthsession session %v... for unconfigured provider '%v'", session.id[:4], session.provider)
			}
			//if _, err := x.parent.DB.Exec("DELETE FROM oauthsession WHERE id = $1", session.id); err != nil {
			//	x.parent.Log.Warnf("Error deleting from oauthsession table for unconfigured provider '%v'", session.provider)
			//} else {
			//	x.parent.Log.Infof("Deleted oauthsession session %v... for unconfigured provider '%v'", session.id[:4], session.provider)
			//}
		} else {
			// Simply making this call will ensure that the oauthsession record is deleted, if it has become invalid.
			// You can see this behaviour in makeAuthenticatedRequest().
			if _, err := x.getUserProfile(session.id, prov); err != nil {
				x.parent.Log.Infof("During OAuth validation, getUserProfile failed on session %v...: %v", session.id[:4], err)
			}
		}
	}

	// The getUserProfile() calls that failed, because of an invalid token, will have removed the relevant entries
	// from the oauthsession table.
	// We can now look for all the entries in the authsession table, which have an orphaned oauthid. These are the
	// Authaus sessions that need to be invalidated.
	authSessions, err := x.OAuthDB.getOrphanAuthSessions()
	//rows, err := x.parent.DB.Query(`SELECT sessionkey FROM authsession WHERE oauthid IS NOT NULL AND oauthid NOT IN (SELECT id FROM oauthsession)`); err != nil {
	if err != nil {
		x.parent.Log.Warnf("Error reading invalid oauth sessions: %v", err)
		return
	} else {
		//keys := []string{}
		//for rows.Next() {
		//	key := ""
		//	if err := rows.Scan(&key); err != nil {
		//		x.parent.Log.Warnf("Error scanning invalid oauth sessions: %v", err)
		//		return
		//	}
		//	keys = append(keys, key)
		//}
		for _, key := range authSessions {
			x.parent.Log.Infof("Logging out session %v..., because the OAuth session is no longer valid", key[:4])
			if err := x.parent.Logout(key); err != nil {
				x.parent.Log.Warnf("Logout of session %v failed: %v", key[:4], err)
			}
		}
	}
}

// Returns the UserId and ErrIdentityExists if the user already exists
func (x *OAuth) createOrGetUserID(profile *OAuthUserProfile) (UserId, error) {
	// Later on, we can think about making nicer username.
	// Right now, I just want to avoid name conflicts.
	username := profile.Email
	user := AuthUser{
		Email:        profile.Email,
		Username:     username,
		Firstname:    profile.FirstName,
		Lastname:     profile.LastName,
		Mobilenumber: profile.Phone,
		Created:      time.Now().UTC(),
		Modified:     time.Now().UTC(),
		Type:         UserTypeOAuth,
		ExternalUUID: profile.UUID,
		CreatedBy:    UserIdOAuthImplicitCreate,
		ModifiedBy:   UserIdOAuthImplicitCreate,
		//Archived             bool
		//PasswordModifiedDate time.Time
		//AccountLocked        bool
	}
	// This password is actually thrown away, but just to be paranoid, we
	// create a long random one which we immediately discard.
	discardedPassword := generateRandomKey(50)
	return x.parent.userStore.CreateIdentity(&user, discardedPassword)
}

func createOAuthURL(provider *ConfigOAuthProvider, sessionID, nonce, pkceChallenge string, r *http.Request) (string, error) {
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far
	if provider.Type != OAuthProviderMSAAD {
		return "", fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
	}

	params := map[string]string{
		"client_id":             provider.ClientID,
		"scope":                 provider.Scope,
		"redirect_uri":          provider.RedirectURL,
		"code_challenge":        pkceChallenge,
		"code_challenge_method": "S256",
		"response_type":         "code",
		"response_mode":         "query",
		"state":                 sessionID,
		"nonce":                 nonce,
	}

	return buildURL(provider.LoginURL, params), nil
}

// Create a code_challenge for Proof Key for Code Exchange.
// It's not our job to verify this.
// The purpose of this is to act as a secret that only we and the server know.
// The attack vector is a middle man who intercepts our redirect_uri, and thus
// gets hold of the authorization code. That authorization code is useless without
// the code challenge, which breaks the middle man's attack.
// In addition, in our original login sequence, we only give the server the hash
// of our code. Then, in subsequent usage of the token that we get back, we send
// through the original (unhashed) plaintext. So the hashing is an additional
// safeguard to prevent an attacker from discovering the secret.
// See https://tools.ietf.org/html/rfc7636, particularly chapter 4 for the protocol details
// This uses the "S256" method
func createPKCE() (verifier, challenge string) {
	// Min length per the spec is 43 characters, and max length is 128.
	// The RFC suggests that you base64 encode 32 bytes of entropy,
	// but generateRandomKey does a similar thing, although it's not base64.
	verifier = generateRandomKey(50)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func buildURL(baseURL string, params map[string]string) string {
	if len(params) == 0 {
		return baseURL
	}
	s := baseURL
	if !strings.HasSuffix(s, "?") {
		s += "?"
	}
	for k, v := range params {
		s += url.QueryEscape(k) + "=" + url.QueryEscape(v) + "&"
	}
	if strings.HasSuffix(s, "&") {
		s = s[0 : len(s)-1]
	}
	return s
}

func buildPOSTBodyForm(params map[string]string) string {
	s := ""
	for k, v := range params {
		s += url.QueryEscape(k) + "=" + url.QueryEscape(v) + "&"
	}
	if strings.HasSuffix(s, "&") {
		s = s[0 : len(s)-1]
	}
	return s
}

type OAuthProvider struct {
	Config ConfigOAuth
	Log    *log.Logger
}

func (x *OAuth) getUserProfile(id string, provider *ConfigOAuthProvider) (*OAuthUserProfile, error) {
	// Microsoft Azure Active Directory is the only provider we've needed to implement so far
	if provider.Type != OAuthProviderMSAAD {
		return nil, fmt.Errorf("Unsupported OAuth provider '%v'", provider.Type)
	}

	ms := &msaadUserProfile{}

	// be careful when using /me as below. It will provide a different UPN
	// than other graph endpoints. For example, /users/{id} will generally provide
	// the user's home tenant UPN appended with other information, while
	// /me will provide the user's home tenant UPN only. See similar comments
	// in msaad.go.
	err := x.getUserProfileHTTP(id, ms)
	if err != nil {
		return nil, err
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

func (x *OAuth) getUserProfileHTTP(id string, ms *msaadUserProfile) error {
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Set("Content-Type", "application/json")
	if err := x.makeAuthenticatedRequestForJSON(id, req, &ms); err != nil {
		return fmt.Errorf("Failed to fetch user profile (%v): %w", id, err)
	}
	if ms.ID == "" {
		return fmt.Errorf("Failed to fetch user profile (%v): no ID", id)
	}
	return nil
}

// Perform an HTTP request, using the token associated with the given ID to authenticate the request.
// If the session token needs to be refreshed, then this function will automatically refresh
// the token.
func (x *OAuth) makeAuthenticatedRequest(id string, r *http.Request) (*http.Response, error) {
	token, err := x.getOrRefreshToken(id)
	if err != nil {
		x.parent.Log.Infof("Failed to refresh OAuth token %v: %v", id[:6], err)

		// In any failure case, ensure that this record no longer exists in the DB.
		// If there are cases that can be retried then that retry logic should be
		// built into getOrRefreshToken()

		if err2 := x.OAuthDB.deleteSession(id); err2 != nil {
			//if _, err := x.parent.DB.Exec("DELETE FROM oauthsession WHERE id = $1", id); err != nil {
			x.parent.Log.Errorf("Failed to delete OAuth session for %v, after failed token refresh: %v", id[:6], err2)
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
	resp, err := x.OAuthProvider.bareHTTP(r, token)
	return resp, err
}

// Wrap makeAuthenticatedRequest, and unmarshal the response into JSON
func (x *OAuth) makeAuthenticatedRequestForJSON(id string, r *http.Request, responseObj interface{}) error {
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

func (x *OAuth) getMe(w http.ResponseWriter, r *http.Request, id string) error {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to build request: %v", err))
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := x.makeAuthenticatedRequest(id, req)
	if err != nil {
		HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Failed to execute authenticated request: %v", err))
		return err
	}

	// forward the response
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
	return nil
}
