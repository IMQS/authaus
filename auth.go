package authaus

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	/* Number of characters from the set [a-zA-Z0-9]. 62^40 = 5 x 10^71, which is 238 bits of entropy.
	Divide that by 2 and we have effective security of 119 bits. This is acceptable, especially
	for a token that cannot be validated without talking to the server.
	*/
	SessionTokenLength = 40
)

var (
	// NOTE: These 'base' error strings may not be prefixes of each other,
	// otherwise it violates our NewError() concept, which ensures that
	// any Authaus error starts with one of these *unique* prefixes
	ErrConnect                = errors.New("Connect failed")
	ErrUnsupported            = errors.New("Unsupported operation")
	ErrIdentityAuthNotFound   = errors.New("Identity authorization not found")
	ErrIdentityPermitNotFound = errors.New("Identity permit not found")
	ErrIdentityEmpty          = errors.New("Identity may not be empty")
	ErrInvalidPassword        = errors.New("Invalid password")
	ErrInvalidSessionToken    = errors.New("Invalid session token")
)

// Use this whenever you return an Authaus error. We rely upon the prefix
// of the error string to identify the broad category of the error.
func NewError(base error, detail string) error {
	return errors.New(base.Error() + ": " + detail)
}

/* For lack of a better name, this is the hub of everything.
 */
type Central struct {
	authenticator          Authenticator
	permitDB               PermitDB
	sessionDB              SessionDB
	NewSessionExpiresAfter time.Duration
}

// A Permit is an opaque binary string that encodes domain-specific roles.
// This could be a string of bits with special meanings, or a blob of JSON, etc.
type Permit struct {
	Roles []byte
}

func (x *Permit) Serialize() string {
	return base64.StdEncoding.EncodeToString(x.Roles)
}

func (x *Permit) Deserialize(encoded string) error {
	*x = Permit{}
	if roles, e := base64.StdEncoding.DecodeString(encoded); e == nil {
		x.Roles = roles
		return nil
	} else {
		return e
	}
	// Unreachable. Remove in Go 1.1
	return nil
}

type Token struct {
	Identity string
	Expires  time.Time
	Permit   Permit
}

func randomString(nchars int, corpus string) string {
	rbytes := make([]byte, nchars)
	rstring := make([]byte, nchars)
	rand.Read(rbytes)
	for i := 0; i < nchars; i++ {
		rstring[i] = corpus[rbytes[i]%byte(len(corpus))]
	}
	return string(rstring)
}

func generateSessionKey() string {
	// It is important not to have any unusual characters in here, especially an equals sign. Old versions of Tomcat
	// will parse such a cookie incorrectly (imagine Cookie: magic=abracadabra=)
	return randomString(SessionTokenLength, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

func NewCentral(authenticator Authenticator, permitDB PermitDB, sessionDB SessionDB) *Central {
	c := &Central{}
	c.authenticator = &sanitizingAuthenticator{
		backend: authenticator,
	}
	c.permitDB = permitDB
	c.sessionDB = newCachedSessionDB(sessionDB)
	c.NewSessionExpiresAfter = 30 * 24 * time.Hour
	return c
}

func NewCentralFromConfig(config *Config) (*Central, error) {
	var err error
	var auth Authenticator
	switch config.Authenticator.Type {
	case "ldap":
		ldapMode, legalLdapMode := configLdapNameToMode[config.Authenticator.Encryption]
		ldapAddress := config.Authenticator.LdapHost
		if config.Authenticator.LdapPort != 0 {
			ldapAddress += ":" + strconv.Itoa(int(config.Authenticator.LdapPort))
		}
		if !legalLdapMode {
			return nil, errors.New(fmt.Sprintf("Unknown ldap mode %v. Recognized modes are TLS, SSL, and empty for unencrypted", config.Authenticator.Encryption))
		}
		if auth, err = NewAuthenticator_LDAP(ldapMode, "tcp", ldapAddress); err != nil {
			return nil, errors.New(fmt.Sprintf("Error creating LDAP Authenticator: %v", err))
		}
	case "dummy":
		auth = NewDummyAuthenticator()
	default:
		return nil, errors.New("Unrecognized Authenticator type '" + config.Authenticator.Type + "'")
	}

	var permitDB PermitDB
	permDBX := config.PermitDB.DBConnection
	if permitDB, err = NewPermitDB_SQL("postgres", permDBX.Host, permDBX.Database, permDBX.User, permDBX.Password, permDBX.SSL); err != nil {
		return nil, errors.New(fmt.Sprintf("Error connecting to PermitDB: %v", err))
	}

	var sessionDB SessionDB
	sessDBX := config.SessionDB.DBConnection
	if sessionDB, err = NewSessionDB_SQL("postgres", sessDBX.Host, sessDBX.Database, sessDBX.User, sessDBX.Password, sessDBX.SSL); err != nil {
		return nil, errors.New(fmt.Sprintf("Error connecting to SessionDB: %v", err))
	}

	return NewCentral(auth, permitDB, sessionDB), nil
}

func (x *Central) debugEnableSessionDB(enable bool) {
	// Used for testing the session cache
	x.sessionDB.(*cachedSessionDB).enableDB = enable
}

func (x *Central) SetSessionCacheSize(maxSessions int) {
	x.sessionDB.(*cachedSessionDB).MaxCachedSessions = maxSessions
}

func (x *Central) GetTokenForSession(sessionkey string) (*Token, error) {
	return x.sessionDB.Read(sessionkey)
}

func (x *Central) GetTokenForIdentityPassword(identity, password string) (*Token, error) {
	if eAuth := x.authenticator.Authenticate(identity, password); eAuth == nil {
		if permit, ePermit := x.permitDB.GetPermit(identity); ePermit == nil {
			t := &Token{}
			t.Expires = veryFarFuture
			t.Identity = identity
			t.Permit = *permit
			return t, nil
		} else {
			return nil, ePermit
		}
	} else {
		return nil, eAuth
	}
	// unreachable (remove in Go 1.1)
	return nil, nil
}

func (x *Central) Login(identity, password string) (sessionkey string, token *Token, e error) {
	token = &Token{}
	token.Identity = identity
	if e = x.authenticator.Authenticate(identity, password); e == nil {
		var permit *Permit
		if permit, e = x.permitDB.GetPermit(identity); e == nil {
			token.Expires = time.Now().Add(x.NewSessionExpiresAfter)
			token.Permit = *permit
			sessionkey = generateSessionKey()
			if e = x.sessionDB.Write(sessionkey, token); e == nil {
				return
			}
		}
	}
	sessionkey = ""
	token = nil
	return
}
