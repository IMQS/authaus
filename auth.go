package authaus

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	//"strconv"
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
	ErrIdentityExists         = errors.New("Identity already exists")
	ErrInvalidPassword        = errors.New("Invalid password")
	ErrInvalidSessionToken    = errors.New("Invalid session token")
)

// Use this whenever you return an Authaus error. We rely upon the prefix
// of the error string to identify the broad category of the error.
func NewError(base error, detail string) error {
	return errors.New(base.Error() + ": " + detail)
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

/*
Token is the result of a successful authentication request. It contains
everything that we know about this authentication event, which includes
the identity that performed the request, when this token expires, and
the permit belonging to this identity.
*/
type Token struct {
	Identity string
	Expires  time.Time
	Permit   Permit
}

// Returns a random string of 'nchars' characters, sampled uniformly from the given corpus of characters.
func RandomString(nchars int, corpus string) string {
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
	return RandomString(SessionTokenLength, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
For lack of a better name, this is the single hub of authentication that you interact with.
All public methods of Central are callable from multiple threads.
*/
type Central struct {
	authenticator          Authenticator
	permitDB               PermitDB
	sessionDB              SessionDB
	roleGroupDB            RoleGroupDB
	NewSessionExpiresAfter time.Duration
}

// Create a new Central object from the specified pieces
// roleGroupDB may be nil
func NewCentral(authenticator Authenticator, permitDB PermitDB, sessionDB SessionDB, roleGroupDB RoleGroupDB) *Central {
	c := &Central{}
	c.authenticator = &sanitizingAuthenticator{
		backend: authenticator,
	}
	c.permitDB = permitDB
	c.sessionDB = newCachedSessionDB(sessionDB)
	if roleGroupDB != nil {
		c.roleGroupDB = NewCachedRoleGroupDB(roleGroupDB)
	}
	c.NewSessionExpiresAfter = 30 * 24 * time.Hour
	return c
}

// Create a new 'Central' object from a Config.
func NewCentralFromConfig(config *Config) (*Central, error) {
	var err error
	var auth Authenticator
	if auth, err = createAuthenticator(&config.Authenticator); err != nil {
		return nil, err
	}

	var permitDB PermitDB
	if permitDB, err = NewPermitDB_SQL(&config.PermitDB.DB); err != nil {
		auth.Close()
		return nil, errors.New(fmt.Sprintf("Error connecting to PermitDB: %v", err))
	}

	var sessionDB SessionDB
	if sessionDB, err = NewSessionDB_SQL(&config.SessionDB.DB); err != nil {
		auth.Close()
		permitDB.Close()
		return nil, errors.New(fmt.Sprintf("Error connecting to SessionDB: %v", err))
	}

	var roleGroupDB RoleGroupDB
	if config.RoleGroupDB.DB.Driver != "" {
		if roleGroupDB, err = NewRoleGroupDB_SQL(&config.RoleGroupDB.DB); err != nil {
			auth.Close()
			permitDB.Close()
			sessionDB.Close()
			return nil, errors.New(fmt.Sprintf("Error connecting to RoleGroupDB: %v", err))
		}
	}

	return NewCentral(auth, permitDB, sessionDB, roleGroupDB), nil
}

func createAuthenticator(config *ConfigAuthenticator) (Authenticator, error) {
	var err error
	var auth Authenticator
	switch config.Type {
	case "ldap":
		ldapMode, legalLdapMode := configLdapNameToMode[config.Encryption]
		//ldapAddress := config.Authenticator.LdapHost
		//if config.Authenticator.LdapPort != 0 {
		//	ldapAddress += ":" + strconv.Itoa(int(config.Authenticator.LdapPort))
		//}
		if !legalLdapMode {
			return nil, errors.New(fmt.Sprintf("Unknown ldap mode %v. Recognized modes are TLS, SSL, and empty for unencrypted", config.Encryption))
		}
		//if auth, err = NewAuthenticator_LDAP(ldapMode, "tcp", ldapAddress); err != nil {
		if auth, err = NewAuthenticator_LDAP(ldapMode, config.LdapHost, uint16(config.LdapPort)); err != nil {
			return nil, errors.New(fmt.Sprintf("Error creating LDAP Authenticator: %v", err))
		}
		return auth, nil
	case "db":
		if auth, err = NewAuthenticationDB_SQL(&config.DB); err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to connect to AuthenticationDB: %v", err))
		}
		return auth, nil
	case "dummy":
		return NewDummyAuthenticator(), nil
	default:
		return nil, errors.New("Unrecognized Authenticator type '" + config.Type + "'")
	}
	// unreachable
	return nil, nil
}

// Set the size of the in-memory session cache
func (x *Central) SetSessionCacheSize(maxSessions int) {
	x.sessionDB.(*cachedSessionDB).MaxCachedSessions = maxSessions
}

// Pass in a session key that was generated with a call to Login(), and get back a token.
// A session key is typically a cookie.
func (x *Central) GetTokenFromSession(sessionkey string) (*Token, error) {
	if token, err := x.sessionDB.Read(sessionkey); err != nil {
		return token, err
	} else {
		if time.Now().UnixNano() > token.Expires.UnixNano() {
			// DB has not yet expired token. It's OK for the DB to be a bit lazy in its cleanup.
			return nil, ErrInvalidSessionToken
		} else {
			return token, err
		}
	}
	// unreachable
	return nil, nil
}

// Perform a once-off authentication
func (x *Central) GetTokenFromIdentityPassword(identity, password string) (*Token, error) {
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

// Create a new session. Returns a session key, which can be used in future to retrieve the token.
// The internal session expiry is controlled with the member NewSessionExpiresAfter.
// The session key is typically sent to the client as a cookie.
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

// Change a Permit.
func (x *Central) SetPermit(identity string, permit *Permit) error {
	if err := x.permitDB.SetPermit(identity, permit); err != nil {
		return err
	}
	return x.sessionDB.PermitChanged(identity, permit)
}

// Change a Password. This invalidates all sessions for this identity.
func (x *Central) SetPassword(identity, password string) error {
	if err := x.authenticator.SetPassword(identity, password); err != nil {
		return err
	}
	return x.sessionDB.InvalidateSessionsForIdentity(identity)
}

// Create an identity in the Authenticator.
// For the equivalent operation in the PermitDB, simply call SetPermit()
func (x *Central) CreateAuthenticatorIdentity(identity, password string) error {
	return x.authenticator.CreateIdentity(identity, password)
}

// Retrieve the Role Group Database (which may be nil)
func (x *Central) GetRoleGroupDB() RoleGroupDB {
	return x.roleGroupDB
}

func (x *Central) Close() {
	if x.authenticator != nil {
		x.authenticator.Close()
		x.authenticator = nil
	}
	if x.permitDB != nil {
		x.permitDB.Close()
		x.permitDB = nil
	}
	if x.sessionDB != nil {
		x.sessionDB.Close()
		x.sessionDB = nil
	}
	if x.roleGroupDB != nil {
		x.roleGroupDB.Close()
		x.roleGroupDB = nil
	}
}

func (x *Central) debugEnableSessionDB(enable bool) {
	// Used for testing the session cache
	x.sessionDB.(*cachedSessionDB).enableDB = enable
}
