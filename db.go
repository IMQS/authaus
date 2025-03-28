package authaus

import (
	"database/sql"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// The number of session records that are stored in the in-process cache
	DefaultSessionCacheSize        = 10000
	NullUserId              UserId = 0
)

// These constants are embedded inside our database (in the table AuthUserStore). They may never change.
const (
	UserTypeDefault AuthUserType = 0 // An internal Authaus user, created by an explicit create user command
	UserTypeLDAP    AuthUserType = 1 // Created via sync from an LDAP server
	UserTypeOAuth   AuthUserType = 2 // Created automatically via an OAuth login
	UserTypeMSAAD   AuthUserType = 3 // Created via sync from Microsoft Azure Active Directory
)

var AuthUserTypeStrings = map[AuthUserType]string{
	UserTypeDefault: "DEFAULT",
	UserTypeLDAP:    "LDAP",
	UserTypeOAuth:   "OAUTH",
	UserTypeMSAAD:   "MSAAD",
}

const (
	UserStatActionLogin   = "login"
	UserStatActionDisable = "disable"
	UserStatActionEnable  = "enable"
)

var (
	veryFarFuture = time.Date(3000, 1, 1, 1, 1, 1, 1, time.UTC)
	nextUserId    UserId
)

type GetIdentitiesFlag int

const (
	GetIdentitiesFlagNone    GetIdentitiesFlag = 0
	GetIdentitiesFlagDeleted GetIdentitiesFlag = 1 << (iota - 1)
)

type AuthCheck int

const (
	AuthCheckDefault         AuthCheck = 0
	AuthCheckPasswordExpired AuthCheck = 1 << (iota - 1)
)

type PasswordEnforcement int

const (
	PasswordEnforcementDefault PasswordEnforcement = 0
	PasswordEnforcementReuse   PasswordEnforcement = 1 << (iota - 1)
)

type UserId int64

const (
	// The value 0 was originally placed in the CreatedBy and ModifiedBy fields of a user's record,
	// when that user was created or modified by the LDAP sync process. Later, we decided to
	// formalize this, which is when UserIdLDAPMerge was born.
	// These constants are embedded inside our DB, in the CreatedBy and ModifiedBy fields of
	// a user's record, so they may not change.
	UserIdAdministrator UserId = 0
	// skip -1, because it's such a frequent "invalid" integer code
	UserIdLDAPMerge           = -2 // Created/Modified by LDAP integration
	UserIdOAuthImplicitCreate = -3 // Created implicitly by OAuth sign-in
	UserIdMSAADMerge          = -4 // Created/Modified by MSAAD integration
	// NOTE:
	// If you add to this list, be sure to update GetUserNameFromUserId() too
)

type AuthUserType int

type userStats struct {
	UserId        sql.NullInt64
	LastLoginDate sql.NullTime
	EnabledDate   sql.NullTime
	DisabledDate  sql.NullTime
}

func (u AuthUserType) CanSetPassword() bool {
	switch u {
	case UserTypeDefault:
		return true
	default:
		return false
	}
}

func (u AuthUserType) CanRenameIdentity() bool {
	switch u {
	case UserTypeDefault:
		return true
	default:
		return false
	}
}

// The primary job of the UserStore, is to store and authenticate users.
// It is also responsible for adding new users, changing passwords etc.
// All operations except for Close must be thread-safe.
type UserStore interface {
	Authenticate(identity, password string, authTypeCheck AuthCheck) error                                        // Return nil error if the username and password are correct, otherwise one of ErrIdentityAuthNotFound or ErrInvalidPassword
	SetPassword(userId UserId, password string, enforceTypeCheck PasswordEnforcement) error                       // This sets the password to a user account
	SetConfig(passwordExpiry time.Duration, oldPasswordHistorySize int, usersExemptFromExpiring []string) error   // If any parameter is zero, then it is ignored
	ResetPasswordStart(userId UserId, expires time.Time) (string, error)                                          // Create a one-time token that can be used to reset the password with a subsequent call to ResetPasswordFinish
	ResetPasswordFinish(userId UserId, token string, password string, enforceTypeCheck PasswordEnforcement) error // Check that token matches the last one generated by ResetPasswordStart, and if so, call SetPassword
	CreateIdentity(user *AuthUser, password string) (UserId, error)                                               // Create a new identity. If the identity already exists, then this must return ErrIdentityExists.
	UpdateIdentity(user *AuthUser) error                                                                          // Update an identity. Change email address or name etc.
	ArchiveIdentity(userId UserId) error                                                                          // Archive an identity
	MatchArchivedUserExtUUID(externalUUID string) (bool, UserId, error)                                           // Match an archived external user
	UnarchiveIdentity(userId UserId) error                                                                        // Unarchive an identity
	SetUserStats(userId UserId, action string) error                                                              // Set the user stats
	GetUserStats(userId UserId) (userStats, error)                                                                // Get the user stats
	// TODO RenameIdentity was deprecated in May 2016, replaced by UpdateIdentity. We need to remove this once PCS team has made the necessary updates
	RenameIdentity(oldIdent, newIdent string) error                        // Rename an identity. Returns ErrIdentityAuthNotFound if oldIdent does not exist. Returns ErrIdentityExists if newIdent already exists.
	GetUserFromIdentity(identity string) (*AuthUser, error)                // Gets the user object from the identity supplied
	LockAccount(userId UserId) error                                       // Locks an account
	UnlockAccount(userId UserId) error                                     // Unlocks an account
	GetUserFromUserId(userId UserId) (*AuthUser, error)                    // Gets the user object from the userId supplied
	GetIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) // Retrieve a list of all identities
	Close()                                                                // Typically used to close a database handle
}

// The LDAP interface allows authentication and the ability to retrieve the LDAP's users and merge them into our system
type LDAP interface {
	Authenticate(identity, password string) error // Return nil if the password is correct, otherwise one of ErrIdentityAuthNotFound or ErrInvalidPassword
	GetLdapUsers() ([]AuthUser, error)            // Retrieve the list of users from ldap
	Close()                                       // Typically used to close a database handle
}

// A Permit database performs no validation. It simply returns the Permit owned by a particular user.
// All operations except for Close must be thread-safe.
type PermitDB interface {
	GetPermit(userId UserId) (*Permit, error) // Retrieve a permit
	GetPermits() (map[UserId]*Permit, error)  // Retrieve all permits as a map from identity to the permit.
	// This should create the permit if it does not exist. A call to this function is
	// followed by a call to SessionDB.PermitChanged. identity is canonicalized before being stored
	SetPermit(userId UserId, permit *Permit) error
	Close() // Typically used to close a database handle
}

// A Session database is essentially a key/value store where the keys are
// session tokens, and the values are tuples of (Identity,Permit).
// All operations except for Close must be thread-safe.
type SessionDB interface {
	Write(sessionkey string, token *Token) error       // Set a token
	Read(sessionkey string) (*Token, error)            // Fetch a token
	Delete(sessionkey string) error                    // Delete a token (used to implement "logout")
	PermitChanged(userId UserId, permit *Permit) error // Assign the new permit to all of the sessions belonging to 'identity'
	InvalidateSessionsForIdentity(userId UserId) error // Delete all sessions belonging to the given identity. This is called after a password has been changed, or an identity renamed.
	GetAllTokens(includeExpired bool) ([]*Token, error)
	GetAllOAuthTokenIDs() ([]string, error)
	Close() // Typically used to close a database handle
}

type AuthUser struct {
	UserId               UserId       `json:"userID"`
	Email                string       `json:"email"`
	Username             string       `json:"userName"`
	Firstname            string       `json:"firstName"`
	Lastname             string       `json:"lastName"`
	Mobilenumber         string       `json:"mobileNumber"`
	Telephonenumber      string       `json:"telephoneNumber`
	Remarks              string       `json:"remarks"`
	Created              time.Time    `json:"created"`
	CreatedBy            UserId       `json:"createdBy"`
	Modified             time.Time    `json:"modified"`
	ModifiedBy           UserId       `json:"modifiedBy"`
	Type                 AuthUserType `json:"type"`
	Archived             bool         `json:"archived"`
	InternalUUID         string       `json:"internalUUID"`
	ExternalUUID         string       `json:"externalUUID"`
	PasswordModifiedDate time.Time    `json:"passwordModifiedDate"`
	AccountLocked        bool         `json:"accountLocked"`
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// UserStore that sanitizes inputs, so that we have more consistency with different backends
type sanitizingUserStore struct {
	enableAuthenticator bool
	backend             UserStore
}

// LDAP that sanitizes inputs, so that we have more consistency with different backends
type sanitizingLDAP struct {
	backend LDAP
}

func cleanIdentity(identity string) string {
	return strings.TrimSpace(identity)
}

func cleanPassword(password string) string {
	return strings.TrimSpace(password)
}

func cleanIdentityPassword(identity, password string) (string, string) {
	return cleanIdentity(identity), cleanPassword(password)
}

func (x *sanitizingUserStore) Authenticate(identity, password string, authTypeCheck AuthCheck) error {
	identity, password = cleanIdentityPassword(identity, password)
	if len(identity) == 0 {
		return ErrIdentityEmpty
	}
	// We COULD make an empty password an error here, but that is not necessarily correct.
	// There may be an anonymous profile which requires no password. LDAP is specifically vulnerable
	// to this, but that is the job of the LDAP driver to verify that it is not performing
	// an anonymous BIND.
	return x.backend.Authenticate(identity, password, authTypeCheck)
}

func (x *sanitizingUserStore) SetConfig(passwordExpiry time.Duration, oldPasswordHistorySize int, usersExemptFromExpiring []string) error {
	return x.backend.SetConfig(passwordExpiry, oldPasswordHistorySize, usersExemptFromExpiring)
}

func (x *sanitizingUserStore) SetPassword(userId UserId, password string, enforceTypeCheck PasswordEnforcement) error {
	password = cleanPassword(password)
	return x.backend.SetPassword(userId, password, enforceTypeCheck)
}

func (x *sanitizingUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	return x.backend.ResetPasswordStart(userId, expires)
}

func (x *sanitizingUserStore) ResetPasswordFinish(userId UserId, token string, password string, enforceTypeCheck PasswordEnforcement) error {
	password = cleanPassword(password)
	if len(password) == 0 {
		return ErrInvalidPassword
	}
	return x.backend.ResetPasswordFinish(userId, token, password, enforceTypeCheck)
}

func (x *sanitizingUserStore) CreateIdentity(user *AuthUser, password string) (UserId, error) {
	user.Username = cleanIdentity(user.Username)
	user.Email = cleanIdentity(user.Email)
	if len(user.Email) == 0 && len(user.Username) == 0 {
		return NullUserId, ErrIdentityEmpty
	}
	password = cleanPassword(password)
	if len(password) == 0 && x.enableAuthenticator {
		return NullUserId, ErrInvalidPassword
	}
	return x.backend.CreateIdentity(user, password)
}

func (x *sanitizingUserStore) UpdateIdentity(user *AuthUser) error {
	user.Email = cleanIdentity(user.Email)
	if len(user.Email) == 0 && len(user.Username) == 0 {
		return ErrIdentityEmpty
	}
	return x.backend.UpdateIdentity(user)
}

func (x *sanitizingUserStore) ArchiveIdentity(userId UserId) error {
	return x.backend.ArchiveIdentity(userId)
}

func (x *sanitizingUserStore) MatchArchivedUserExtUUID(externalUUID string) (bool, UserId, error) {
	return x.backend.MatchArchivedUserExtUUID(externalUUID)
}

func (x *sanitizingUserStore) UnarchiveIdentity(userId UserId) error {
	return x.backend.UnarchiveIdentity(userId)
}

func (x *sanitizingUserStore) SetUserStats(userId UserId, action string) error {
	return x.backend.SetUserStats(userId, action)
}

func (x *sanitizingUserStore) GetUserStats(userId UserId) (userStats, error) {
	return x.backend.GetUserStats(userId)
}

func (x *sanitizingUserStore) RenameIdentity(oldIdent, newIdent string) error {
	oldIdent, _ = cleanIdentityPassword(oldIdent, "")
	newIdent, _ = cleanIdentityPassword(newIdent, "")
	if len(oldIdent) == 0 || len(newIdent) == 0 {
		return ErrIdentityEmpty
	}
	if oldIdent == newIdent {
		return nil
	}
	return x.backend.RenameIdentity(oldIdent, newIdent)
}

func (x *sanitizingUserStore) GetIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) {
	return x.backend.GetIdentities(getIdentitiesFlag)
}

func (x *sanitizingUserStore) GetUserFromIdentity(identity string) (*AuthUser, error) {
	return x.backend.GetUserFromIdentity(identity)
}

func (x *sanitizingUserStore) GetUserFromUserId(userId UserId) (*AuthUser, error) {
	return x.backend.GetUserFromUserId(userId)
}

func (x *sanitizingUserStore) LockAccount(userId UserId) error {
	return x.backend.LockAccount(userId)
}

func (x *sanitizingUserStore) UnlockAccount(userId UserId) error {
	return x.backend.UnlockAccount(userId)
}

func (x *sanitizingUserStore) Close() {
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

func (x *sanitizingLDAP) Authenticate(identity, password string) error {
	identity, password = cleanIdentityPassword(identity, password)
	if len(identity) == 0 {
		return ErrIdentityEmpty
	}
	// We COULD make an empty password an error here, but that is not necessarily correct.
	// There may be an anonymous profile which requires no password. LDAP is specifically vulnerable
	// to this, but that is the job of the LDAP driver to verify that it is not performing
	// an anonymous BIND.
	return x.backend.Authenticate(identity, password)
}

func (x *sanitizingLDAP) GetLdapUsers() ([]AuthUser, error) {
	return x.backend.GetLdapUsers()
}

func (x *sanitizingLDAP) Close() {
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Chained ? BAD IDEA. This introduces too much ambiguity into the system.
/*
// Chain of authenticators. Each one is tried in order.
// If you have a high latency Authenticator, then you should place that last in the chain
type ChainedAuthenticator struct {
	chain []Authenticator
}

func (x *ChainedAuthenticator) Authenticate(identity, password string) error {
	for _, a := range x.chain {
		if err := a.Authenticate(identity, password); err == nil {
			return nil
		} else if err.Error().Index(ErrInvalidPassword) == 0 {
			return ErrInvalidPassword
		}
	}
	return ErrIdentityAuthNotFound
}

func (x *ChainedAuthenticator) SetPassword(identity, password string) error {
	firstError := ErrIdentityAuthNotFound
	for _, a := range x.chain {
		if err := a.SetPassword(identity, password); err == nil {
			return nil
		} else if firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (x *ChainedAuthenticator) Close() {
	for _, a := range x.chain {
		a.Close()
	}
	x.chain = make([]Authenticator, 0)
}
*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Session database that simply stores the sessions in memory
type dummySessionDB struct {
	sessions     map[string]*Token
	sessionsLock sync.RWMutex
}

func newDummySessionDB() *dummySessionDB {
	db := &dummySessionDB{}
	db.sessions = make(map[string]*Token)
	return db
}

func (x *dummySessionDB) Write(sessionkey string, token *Token) error {
	x.sessionsLock.Lock()
	x.sessions[sessionkey] = token
	x.sessionsLock.Unlock()
	return nil
}

func (x *dummySessionDB) Read(sessionkey string) (*Token, error) {
	x.sessionsLock.RLock()
	token, exists := x.sessions[sessionkey]
	x.sessionsLock.RUnlock()
	if !exists {
		return nil, ErrInvalidSessionToken
	}
	return token, nil
}

func (x *dummySessionDB) GetAllTokens(includeExpired bool) ([]*Token, error) {
	//TODO implement me
	panic("implement me")
}
func (x *dummySessionDB) GetAllOAuthTokenIDs() ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (x *dummySessionDB) Delete(sessionkey string) error {
	x.sessionsLock.Lock()
	delete(x.sessions, sessionkey)
	x.sessionsLock.Unlock()
	return nil
}

func (x *dummySessionDB) PermitChanged(userId UserId, permit *Permit) error {
	x.sessionsLock.Lock()
	for _, ses := range x.sessionKeysForIdentity(userId) {
		x.sessions[ses].Permit = *permit
	}
	x.sessionsLock.Unlock()
	return nil
}

func (x *dummySessionDB) InvalidateSessionsForIdentity(userId UserId) error {
	x.sessionsLock.Lock()
	for _, ses := range x.sessionKeysForIdentity(userId) {
		delete(x.sessions, ses)
	}
	x.sessionsLock.Unlock()
	return nil
}

func (x *dummySessionDB) Close() {
}

// Assume that sessionLock.READ is held
func (x *dummySessionDB) sessionKeysForIdentity(userId UserId) []string {
	sessions := []string{}
	for ses, p := range x.sessions {
		if p.UserId == userId {
			sessions = append(sessions, ses)
		}
	}
	return sessions
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type cachedToken struct {
	sessionkey string // We duplicate this to make pruning easy (ie preserve sessionkey after sorting)
	date       time.Time
	token      *Token
}

type cachedTokenSlice []*cachedToken

func (x cachedTokenSlice) Len() int           { return len(x) }
func (x cachedTokenSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
func (x cachedTokenSlice) Less(i, j int) bool { return x[i].date.UnixNano() < x[j].date.UnixNano() }

// Session DB that adds a memory cache of sessions
type cachedSessionDB struct {
	MaxCachedSessions  int // Maximum number of cached sessions
	cachedSessions     map[string]*cachedToken
	cachedSessionsLock sync.RWMutex
	db                 SessionDB
	enableDB           bool // Used by tests to disable DB reads/writes
}

func newCachedSessionDB(storage SessionDB) *cachedSessionDB {
	c := &cachedSessionDB{}
	c.MaxCachedSessions = DefaultSessionCacheSize
	c.db = storage
	c.cachedSessions = make(map[string]*cachedToken)
	c.enableDB = true
	return c
}

// Assume that cachedSessionLock.WRITE is held
func (x *cachedSessionDB) prune() {
	if len(x.cachedSessions) > x.MaxCachedSessions {
		// delete the oldest half
		now := time.Now()
		tokens := make(cachedTokenSlice, len(x.cachedSessions))
		i := 0
		for _, p := range x.cachedSessions {
			tokens[i] = p
			i += 1
		}
		sort.Sort(tokens)
		//fmt.Printf("Pruning\n")
		//for j := 0; j < len(tokens); j += 1 {
		//	fmt.Printf("%v %v (%v)\n", tokens[j].date, tokens[j].token, j <= x.MaxCachedSessions/2)
		//}
		//fmt.Printf("\n")
		tokens = tokens[x.MaxCachedSessions/2:]
		x.cachedSessions = make(map[string]*cachedToken)
		for _, p := range tokens {
			if p.token.Expires.Unix() > now.Unix() {
				x.cachedSessions[p.sessionkey] = p
			}
		}
	}
}

// Assume that no lock is held on cachedSessionLock
func (x *cachedSessionDB) insert(sessionkey string, token *Token) {
	cp := &cachedToken{}
	cp.date = time.Now()
	cp.sessionkey = sessionkey
	cp.token = token
	x.cachedSessionsLock.Lock()
	x.cachedSessions[sessionkey] = cp
	x.prune()
	x.cachedSessionsLock.Unlock()
}

func (x *cachedSessionDB) Write(sessionkey string, token *Token) (err error) {
	// Since the pair (sessionkey, token) is unique, we need not worry about a race
	// condition causing a discrepancy between the DB sessions and our cached sessions.
	// Expanding the lock to cover x.db.Write would incur a significant performance penalty.
	if err = x.db.Write(sessionkey, token); err == nil {
		x.insert(sessionkey, token)
	}
	return
}

func (x *cachedSessionDB) Read(sessionkey string) (*Token, error) {
	x.cachedSessionsLock.RLock()
	cached := x.cachedSessions[sessionkey]
	x.cachedSessionsLock.RUnlock()
	// Despite being outside of the reader lock, our cachedToken is still valid, because
	// it will only get cleaned up by the garbage collector, not by a prune or anything else.
	if cached != nil {
		return cached.token, nil
	} else {
		if x.enableDB {
			if token, err := x.db.Read(sessionkey); err == nil {
				x.insert(sessionkey, token)
				return token, nil
			} else {
				return nil, err
			}
		} else {
			return nil, ErrInvalidSessionToken
		}
	}
}

func (x *cachedSessionDB) GetAllTokens(includeExpired bool) ([]*Token, error) {
	return x.db.GetAllTokens(includeExpired)
}

func (x *cachedSessionDB) GetAllOAuthTokenIDs() ([]string, error) {
	return x.db.GetAllOAuthTokenIDs()
}

func (x *cachedSessionDB) Delete(sessionkey string) error {
	// First delete from the DB, and then from the cache
	if x.enableDB {
		if err := x.db.Delete(sessionkey); err != nil {
			return err
		}
	}
	x.cachedSessionsLock.Lock()
	delete(x.cachedSessions, sessionkey)
	x.cachedSessionsLock.Unlock()
	return nil
}

func (x *cachedSessionDB) PermitChanged(userId UserId, permit *Permit) error {
	// PermitChanged is called AFTER a permit has already been altered, so our
	// first action is to update our cache, because that cannot fail.
	// Thereafter, we try to modify the session database, which is beyond our control.
	x.cachedSessionsLock.Lock()
	for _, ses := range x.sessionKeysForIdentity(userId) {
		x.cachedSessions[ses].token.Permit = *permit
	}
	x.cachedSessionsLock.Unlock()
	return x.db.PermitChanged(userId, permit)
}

func (x *cachedSessionDB) InvalidateSessionsForIdentity(userId UserId) error {
	x.cachedSessionsLock.Lock()
	for _, ses := range x.sessionKeysForIdentity(userId) {
		delete(x.cachedSessions, ses)
	}
	x.cachedSessionsLock.Unlock()
	return x.db.InvalidateSessionsForIdentity(userId)
}

func (x *cachedSessionDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

// Assume that cachedSessionsLock.READ is held
func (x *cachedSessionDB) sessionKeysForIdentity(userId UserId) []string {
	sessions := []string{}
	for ses, cached := range x.cachedSessions {
		if cached.token.UserId == userId {
			sessions = append(sessions, ses)
		}
	}
	return sessions
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Permit database that is simply a map
type dummyPermitDB struct {
	permits     map[UserId]*Permit
	permitsLock sync.RWMutex
}

func newDummyPermitDB() *dummyPermitDB {
	db := &dummyPermitDB{}
	db.permits = make(map[UserId]*Permit)
	return db
}

func (x *dummyPermitDB) GetPermit(userId UserId) (*Permit, error) {
	x.permitsLock.RLock()
	permit := x.permits[userId]
	x.permitsLock.RUnlock()
	if permit != nil {
		return permit.Clone(), nil
	} else {
		return nil, ErrIdentityPermitNotFound
	}
}

func (x *dummyPermitDB) GetPermits() (map[UserId]*Permit, error) {
	x.permitsLock.RLock()
	copy := make(map[UserId]*Permit)
	for k, v := range x.permits {
		copy[k] = v.Clone()
	}
	x.permitsLock.RUnlock()
	return copy, nil
}

func (x *dummyPermitDB) SetPermit(userId UserId, permit *Permit) error {
	x.permitsLock.Lock()
	x.permits[userId] = permit
	x.permitsLock.Unlock()
	return nil
}

func (x *dummyPermitDB) Close() {
}

func (a *AuthUser) getIdentity() string {
	if len(a.Email) == 0 {
		return a.Username
	}
	return a.Email
}
