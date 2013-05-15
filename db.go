package authaus

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// The number of session records that are stored in the in-process cache
	DefaultSessionCacheSize = 10000
)

var (
	veryFarFuture = time.Date(3000, 1, 1, 1, 1, 1, 1, time.UTC)
)

// The only job of an authenticator is to validate an identity/password
type Authenticator interface {
	Authenticate(identity, password string) error // Return nil if the password is correct, otherwise one of ErrIdentityAuthNotFound or ErrInvalidPassword
	SetPassword(identity, password string) error  // This should create the identity if it does not exist
	Close()                                       // Typically used to close a database handle
}

// A Permit database performs no validation. It simply returns the Permit owned by a particular user.
type PermitDB interface {
	GetPermit(identity string) (*Permit, error)
	// This should create the permit if it does not exist. A call to this function should be followed
	// by a call to SessionDB.PermitChanged.
	SetPermit(identity string, permit *Permit) error
}

// A Session database is essentially a key/value store where the keys are
// session tokens, and the values are Permits
type SessionDB interface {
	Write(sessionkey string, token *Token) error
	// Returns the expiry time of the permit
	Read(sessionkey string) (*Token, error)
	// This is called after a permit has been changed. The Session DB must alter all existing tokens
	// that belong to this Identity.
	// If permit is not nil, then assign the new permit to all of the sessions belonging to permit.Identity
	// If permit is nil, then erase all sessions belonging to that identity
	PermitChanged(identity string, permit *Permit) error
	Close() // Typically used to close a database handle
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Authenticator that simply stores identity/passwords in memory
type dummyAuthenticator struct {
	passwords     map[string]string
	passwordsLock sync.RWMutex
}

func NewDummyAuthenticator() *dummyAuthenticator {
	d := &dummyAuthenticator{}
	d.passwords = make(map[string]string)
	return d
}

func (x *dummyAuthenticator) Authenticate(identity, password string) error {
	x.passwordsLock.RLock()
	truth, exists := x.passwords[identity]
	x.passwordsLock.RUnlock()
	if !exists {
		return ErrIdentityAuthNotFound
	} else if truth == password {
		return nil
	} else {
		return ErrInvalidPassword
	}
	// unreachable (can remove in Go 1.1)
	return nil
}

func (x *dummyAuthenticator) SetPassword(identity, password string) error {
	x.passwordsLock.Lock()
	x.passwords[identity] = password
	x.passwordsLock.Unlock()
	return nil
}

func (x *dummyAuthenticator) Close() {
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Authenticator that sanitizes inputs, so that we have more consistency with different backends
type sanitizingAuthenticator struct {
	backend Authenticator
}

func cleanIdentityPassword(identity, password string) (string, string) {
	return strings.TrimSpace(identity), strings.TrimSpace(password)
}

func (x *sanitizingAuthenticator) Authenticate(identity, password string) error {
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

func (x *sanitizingAuthenticator) SetPassword(identity, password string) error {
	identity, password = cleanIdentityPassword(identity, password)
	if len(identity) == 0 {
		return ErrIdentityEmpty
	}
	return x.backend.SetPassword(identity, password)
}

func (x *sanitizingAuthenticator) Close() {
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

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

func (x *dummySessionDB) PermitChanged(identity string, permit *Permit) error {
	x.sessionsLock.Lock()
	// Find tokens belonging to this identity
	tokens := []string{}
	for tok, p := range x.sessions {
		if p.Identity == identity {
			tokens = append(tokens, tok)
		}
	}
	// Reset all those tokens
	for _, tok := range tokens {
		if permit != nil {
			x.sessions[tok].Permit = *permit
		} else {
			delete(x.sessions, tok)
		}
	}
	x.sessionsLock.Unlock()
	return nil
}

func (x *dummySessionDB) Close() {
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
	enableDB           bool
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

func (x *cachedSessionDB) Write(sessionkey string, token *Token) error {
	if err := x.db.Write(sessionkey, token); err == nil {
		x.insert(sessionkey, token)
		return nil
	} else {
		return err
	}
	// unreachable (remove in Go 1.1)
	return nil
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
	// unreachable (remove in Go 1.1)
	return nil, nil
}

func (x *cachedSessionDB) PermitChanged(identity string, permit *Permit) error {
	x.cachedSessionsLock.Lock()
	tokens := []string{}
	for tok, cached := range x.cachedSessions {
		if cached.token.Identity == identity {
			tokens = append(tokens, tok)
		}
	}
	for _, tok := range tokens {
		if permit != nil {
			x.cachedSessions[tok].token.Permit = *permit
		} else {
			delete(x.cachedSessions, tok)
		}
	}
	x.cachedSessionsLock.Unlock()
	return x.db.PermitChanged(identity, permit)
}

func (x *cachedSessionDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Permit database that is simply a map
type dummyPermitDB struct {
	permits     map[string]*Permit
	permitsLock sync.RWMutex
}

func newDummyPermitDB() *dummyPermitDB {
	db := &dummyPermitDB{}
	db.permits = make(map[string]*Permit)
	return db
}

func (x *dummyPermitDB) GetPermit(identity string) (*Permit, error) {
	x.permitsLock.RLock()
	permit := x.permits[identity]
	x.permitsLock.RUnlock()
	if permit != nil {
		return permit, nil
	} else {
		return permit, ErrIdentityPermitNotFound
	}
	// unreachable (remove in Go 1.1)
	return nil, nil
}

func (x *dummyPermitDB) SetPermit(identity string, permit *Permit) error {
	x.permitsLock.Lock()
	x.permits[identity] = permit
	x.permitsLock.Unlock()
	return nil
}
