package authaus

import (
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
	UserTypeDefault AuthUserType = 0
	UserTypeLDAP    AuthUserType = 1
)

var (
	veryFarFuture = time.Date(3000, 1, 1, 1, 1, 1, 1, time.UTC)
	nextUserId    UserId
)

type UserId int64

type AuthUserType int

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

func (u AuthUserType) EmailAsIdentity() bool {
	switch u {
	case UserTypeDefault:
		return true
	default:
		return false
	}
}

func (u AuthUserType) UsernameAsIdentity() bool {
	switch u {
	case UserTypeLDAP:
		return true
	default:
		return false
	}
}

// The primary job of the UserStore, is to store and authenticate users.
// It is also responsible for adding new users, changing passwords etc.
// All operations except for Close must be thread-safe.
type UserStore interface {
	Authenticate(identity, password string) error                                                                                  // Return nil error if the username and password are correct, otherwise one of ErrIdentityAuthNotFound or ErrInvalidPassword
	SetPassword(userId UserId, password string) error                                                                              // This sets the password to a user account
	ResetPasswordStart(userId UserId, expires time.Time) (string, error)                                                           // Create a one-time token that can be used to reset the password with a subsequent call to ResetPasswordFinish
	ResetPasswordFinish(userId UserId, token string, password string) error                                                        // Check that token matches the last one generated by ResetPasswordStart, and if so, call SetPassword
	CreateIdentity(email, username, firstname, lastname, mobilenumber, password string, authUserType AuthUserType) (UserId, error) // Create a new identity. If the identity already exists, then this must return ErrIdentityExists.
	UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string, authUserType AuthUserType) error      // Update an identity. Change email address or name etc.
	ArchiveIdentity(userId UserId) error                                                                                           // Archive an identity
	// TODO RenameIdentity was deprecated in May 2016, replaced by UpdateIdentity. We need to remove this once PCS team has made the necessary updates
	RenameIdentity(oldIdent, newIdent string) error        // Rename an identity. Returns ErrIdentityAuthNotFound if oldIdent does not exist. Returns ErrIdentityExists if newIdent already exists.
	GetUserFromIdentity(identity string) (AuthUser, error) // Gets the user object from the identity supplied
	GetUserFromUserId(userId UserId) (AuthUser, error)     // Gets the user object from the userId supplied
	GetIdentities() ([]AuthUser, error)                    // Retrieve a list of all identities
	Close()                                                // Typically used to close a database handle
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
	Close()                                            // Typically used to close a database handle
}

type AuthUser struct {
	UserId       UserId
	Email        string
	Username     string
	Firstname    string
	Lastname     string
	Mobilenumber string
	Type         AuthUserType
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Authenticator/Userstore that simply stores identity/passwords in memory
type dummyUserStore struct {
	users     map[UserId]*dummyUser
	usersLock sync.RWMutex
}

type dummyLdapUser struct {
	username     string
	email        string
	firstname    string
	lastname     string
	mobilenumber string
	password     string
}

type dummyLdap struct {
	ldapUsers []*dummyLdapUser
	usersLock sync.RWMutex
}

type dummyUser struct {
	userId             UserId
	email              string
	username           string
	firstname          string
	lastname           string
	mobilenumber       string
	password           string
	passwordResetToken string
	archived           bool
	authUserType       AuthUserType
}

func newDummyUserStore() *dummyUserStore {
	d := &dummyUserStore{}
	d.users = make(map[UserId]*dummyUser)
	return d
}

func newDummyLdap() *dummyLdap {
	d := &dummyLdap{}
	d.ldapUsers = make([]*dummyLdapUser, 0)
	return d
}

func (x *dummyUserStore) Authenticate(identity, password string) (er error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	user := x.getDummyUser(identity)
	if user == nil {
		er = ErrIdentityAuthNotFound
	} else if user.password == password {
		er = nil
	} else {
		er = ErrInvalidPassword
	}

	return
}

func (x *dummyUserStore) Close() {
	//Set incrementing user id to 0, for unit test prediction
	nextUserId = 0
}

func (x *dummyUserStore) SetPassword(userId UserId, password string) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && user.authUserType.CanSetPassword() {
		user.password = password
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived && user.authUserType.CanSetPassword() {
		user.passwordResetToken = generatePasswordResetToken(expires)
		return user.passwordResetToken, nil
	} else {
		return "", ErrIdentityAuthNotFound
	}
}

func (x *dummyUserStore) ResetPasswordFinish(userId UserId, token string, password string) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived && user.authUserType.CanSetPassword() {
		if err := verifyPasswordResetToken(token, user.passwordResetToken); err != nil {
			return err
		}
		user.password = password
		user.passwordResetToken = ""
		return nil
	} else {
		return ErrIdentityAuthNotFound
	}
}

func (x *dummyUserStore) CreateIdentity(email, username, firstname, lastname, mobilenumber, password string, authUserType AuthUserType) (UserId, error) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	var user *dummyUser
	if authUserType.EmailAsIdentity() {
		user = x.getDummyUser(email)
	} else if authUserType.UsernameAsIdentity() {
		user = x.getDummyUser(username)
	}
	if user == nil {
		userId := x.generateUserId()
		x.users[userId] = &dummyUser{userId, email, username, firstname, lastname, mobilenumber, password, "", false, authUserType}
		return userId, nil
	} else {
		return NullUserId, ErrIdentityExists
	}
}

func (x *dummyUserStore) UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string, authUserType AuthUserType) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived {
		user.email = email
		user.username = username
		user.firstname = firstname
		user.lastname = lastname
		user.mobilenumber = mobilenumber
		user.authUserType = authUserType
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) ArchiveIdentity(userId UserId) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists {
		user.archived = true
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) RenameIdentity(oldEmail, newEmail string) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()

	newKey := CanonicalizeIdentity(newEmail)
	oldEmail = CanonicalizeIdentity(oldEmail)
	newUser := x.getDummyUser(newKey)
	if newUser == nil {
		oldUser := x.getDummyUser(oldEmail)

		if oldUser != nil && !oldUser.archived && oldUser.authUserType == UserTypeDefault {
			x.users[oldUser.userId].email = newEmail
			return nil
		} else {
			return ErrIdentityAuthNotFound
		}
	} else {
		return ErrIdentityExists
	}
}

func (x *dummyUserStore) GetIdentities() ([]AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	list := []AuthUser{}
	for _, v := range x.users {
		if v.archived == false {
			list = append(list, AuthUser{v.userId, v.email, v.username, v.firstname, v.lastname, v.mobilenumber, v.authUserType})
		}
	}
	return list, nil
}

func (x *dummyUserStore) GetUserFromIdentity(identity string) (AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	for _, v := range x.users {
		if CanonicalizeIdentity(v.email) == CanonicalizeIdentity(identity) && v.archived == false {
			return AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType}, nil
		} else if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) && v.archived == false {
			return AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType}, nil
		}
	}

	return AuthUser{}, ErrIdentityAuthNotFound
}

func (x *dummyUserStore) GetUserFromUserId(userId UserId) (AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	for _, v := range x.users {
		if v.userId == userId && v.archived == false {
			return AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType}, nil
		}
	}

	return AuthUser{}, ErrIdentityAuthNotFound
}

func (x *dummyUserStore) getDummyUser(identity string) *dummyUser {
	for _, v := range x.users {
		if CanonicalizeIdentity(v.email) == CanonicalizeIdentity(identity) && v.archived == false {
			return v
		} else if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) && v.archived == false {
			return v
		}
	}
	return nil
}

func (x *dummyUserStore) generateUserId() UserId {
	nextUserId = nextUserId + 1
	return nextUserId
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (x *dummyLdap) Authenticate(identity, password string) (er error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	user := x.getLdapUser(identity)
	if user == nil {
		er = ErrInvalidCredentials
	} else if len(password) == 0 {
		er = ErrInvalidPassword
	} else if user.password == password {
		er = nil
	} else {
		er = ErrInvalidCredentials
	}

	return
}

func (x *dummyLdap) GetLdapUsers() ([]AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	//Now we build up and return the list of ldap users ([]AuthUsers)
	ldapUsers := make([]AuthUser, 0)
	for _, ldapUser := range x.ldapUsers {
		ldapUsers = append(ldapUsers, AuthUser{UserId: NullUserId, Email: ldapUser.email, Username: ldapUser.username, Firstname: ldapUser.firstname, Lastname: ldapUser.lastname, Mobilenumber: ldapUser.mobilenumber, Type: UserTypeLDAP})
	}
	return ldapUsers, nil
}

func (x *dummyLdap) getLdapUser(identity string) *dummyLdapUser {
	for _, v := range x.ldapUsers {
		if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) {
			return v
		}
	}
	return nil
}

func (x *dummyLdap) AddLdapUser(username, password, email, name, surname, mobile string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	user := dummyLdapUser{
		username:     username,
		email:        email,
		firstname:    name,
		lastname:     surname,
		mobilenumber: mobile,
		password:     password,
	}
	x.ldapUsers = append(x.ldapUsers, &user)
}

func (x *dummyLdap) UpdateLdapUser(username, email, name, surname, mobile string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	for _, ldapUser := range x.ldapUsers {
		if ldapUser.username == username {
			ldapUser.email = email
			ldapUser.firstname = name
			ldapUser.lastname = surname
			ldapUser.mobilenumber = mobile
		}
	}
}

func (x *dummyLdap) RemoveLdapUser(username string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	for i, ldapUser := range x.ldapUsers {
		if ldapUser.username == username {
			x.ldapUsers = append(x.ldapUsers[:i], x.ldapUsers[i+1:]...)
			break
		}
	}
}

func (x *dummyLdap) Close() {
	//Set incrementing user id to 0, for unit test prediction
	nextUserId = 0
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

func (x *sanitizingUserStore) Authenticate(identity, password string) error {
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

func (x *sanitizingUserStore) SetPassword(userId UserId, password string) error {
	password = cleanPassword(password)
	return x.backend.SetPassword(userId, password)
}

func (x *sanitizingUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	return x.backend.ResetPasswordStart(userId, expires)
}

func (x *sanitizingUserStore) ResetPasswordFinish(userId UserId, token string, password string) error {
	password = cleanPassword(password)
	if len(password) == 0 {
		return ErrInvalidPassword
	}
	return x.backend.ResetPasswordFinish(userId, token, password)
}

func (x *sanitizingUserStore) CreateIdentity(email, username, firstname, lastname, mobilenumber, password string, authUserType AuthUserType) (UserId, error) {
	username = cleanIdentity(username)
	email = cleanIdentity(email)
	if len(email) == 0 && len(username) == 0 {
		return NullUserId, ErrIdentityEmpty
	}
	password = cleanPassword(password)
	if len(password) == 0 && x.enableAuthenticator {
		return NullUserId, ErrInvalidPassword
	}
	return x.backend.CreateIdentity(email, username, firstname, lastname, mobilenumber, password, authUserType)
}

func (x *sanitizingUserStore) UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string, authUserType AuthUserType) error {
	email = cleanIdentity(email)
	if len(email) == 0 && len(username) == 0 {
		return ErrIdentityEmpty
	}
	return x.backend.UpdateIdentity(userId, email, username, firstname, lastname, mobilenumber, authUserType)
}

func (x *sanitizingUserStore) ArchiveIdentity(userId UserId) error {
	return x.backend.ArchiveIdentity(userId)
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

func (x *sanitizingUserStore) GetIdentities() ([]AuthUser, error) {
	return x.backend.GetIdentities()
}

func (x *sanitizingUserStore) GetUserFromIdentity(identity string) (AuthUser, error) {
	return x.backend.GetUserFromIdentity(identity)
}

func (x *sanitizingUserStore) GetUserFromUserId(userId UserId) (AuthUser, error) {
	return x.backend.GetUserFromUserId(userId)
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
