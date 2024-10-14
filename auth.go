package authaus

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IMQS/log"
)

const (
	/* Number of characters from the set [a-zA-Z0-9] = 62. 62^30 = 6 x 10^53, which is 178 bits of entropy.
	Assume there will be 1 million valid tokens. That removes 20 bits of entropy, leaving 158 bits.
	Divide 158 by 2 and we have a security level of 79 bits. If an attacker can try 100000 tokens per
	second, then it would take 2 * 10^11 years to find a random good token.
	*/
	sessionTokenLength = 30

	defaultSessionExpirySeconds = 30 * 24 * 3600

	defaultSyncMergeTickerSeconds = 3 * 60
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
	// We should perhaps keep a consistent error, like ErrInvalidCredentials throught the app, as it can be a security risk returning InvalidPassword to a user that may be malicious
	ErrInvalidPassword      = errors.New("Invalid password")
	ErrAccountLocked        = errors.New("Account locked. Please contact your administrator")
	ErrInvalidSessionToken  = errors.New("Invalid session token")
	ErrInvalidPasswordToken = errors.New("Invalid password token")
	ErrPasswordTokenExpired = errors.New("Password token has expired")
	ErrPasswordExpired      = errors.New("Password has expired")
	ErrInvalidPastPassword  = errors.New("Invalid previously used password")
	ErrInvalidCredentials   = errors.New("Invalid Credentials") // This error was created for LDAP authentication. LDAP does not return 'identity not found' or 'invalid password' but simply invalid credentials
)

// NewError is to be used whenever you return an Authaus error. We rely upon the
// prefix of the error string to identify the broad category of the error.
func NewError(base error, detail string) error {
	return errors.New(base.Error() + ": " + detail)
}

// A Permit is an opaque binary string that encodes domain-specific roles.
// This could be a string of bits with special meanings, or a blob of JSON, etc.
type Permit struct {
	Roles []byte
}

// ToString puts out the string representation of the permit - only intended to
// be used as a speedy debug helper
func (p *Permit) ToString() string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// Clone returns a copy of the permit
func (p *Permit) Clone() *Permit {
	cpy := &Permit{}
	cpy.Roles = make([]byte, len(p.Roles))
	copy(cpy.Roles, p.Roles)
	return cpy
}

// Serialize returns a base64 representation of the permit
func (p *Permit) Serialize() string {
	return base64.StdEncoding.EncodeToString(p.Roles)
}

// Deserialize decodes the encoded parameter and stores it in the native
// permit struct
func (p *Permit) Deserialize(encoded string) error {
	*p = Permit{}
	if roles, e := base64.StdEncoding.DecodeString(encoded); e == nil {
		p.Roles = roles
		return nil
	} else {
		return e
	}
}

// Equals compares whether or not the roles in the resepective permits are equal
func (p *Permit) Equals(b *Permit) bool {
	return bytes.Equal(p.Roles, b.Roles)
}

/*
Token is the result of a successful authentication request. It contains
everything that we know about this authentication event, which includes
the identity that performed the request, when this token expires, and
the permit belonging to this identity.
*/
type Token struct {
	Identity       string
	UserId         UserId
	Email          string
	Username       string
	InternalUUID   string
	Expires        time.Time
	Permit         Permit
	OAuthSessionID string // Only applicable if this login occurred via OAuth
}

// CanonicalizeIdentity transforms an identity into its canonical form. What this
// means is that any two identities are considered equal if their canonical forms
// are equal. This is simply a lower-casing of the identity, so that
// "bob@enterprise.com" is equal to "Bob@enterprise.com".
// It also trims the whitespace around the identity.
func CanonicalizeIdentity(identity string) string {
	return strings.TrimSpace(strings.ToLower(identity))
}

// RandomString returns a random string of 'nchars' bytes, sampled uniformly from the given corpus of byte characters.
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
	return generateRandomKey(sessionTokenLength)
}

func generateRandomKey(length int) string {
	// It is important not to have any unusual characters in here, especially an equals sign. Old versions of Tomcat
	// will parse such a cookie incorrectly (imagine Cookie: magic=abracadabra=)
	return RandomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

func generatePasswordResetToken(expires time.Time) string {
	return fmt.Sprintf("%v.%v", expires.Unix(), generateSessionKey())
}

// Returns nil if the token is parseable, not expired, and matches truthToken
func verifyPasswordResetToken(candidateToken, truthToken string) error {
	// NOTE: If you ever alter the format of the token, ensure that an empty token
	// remains invalid. Right now, if truthToken is empty, then this function
	// will fail, because candidateToken must therefore also be empty, and because of that,
	// the split by "." will fail, and that is what will cause the token to be invalid.
	// This is a very round-about way of ensuring that an empty token is invalid, but
	// it is correct.
	pieces := strings.Split(candidateToken, ".")
	if len(pieces) != 2 {
		return ErrInvalidPasswordToken
	}
	dateInt, err := strconv.ParseInt(pieces[0], 10, 64)
	if err != nil {
		return ErrInvalidPasswordToken
	}
	if time.Now().After(time.Unix(dateInt, 0)) {
		return ErrPasswordTokenExpired
	}
	if subtle.ConstantTimeCompare([]byte(candidateToken), []byte(truthToken)) != 1 {
		return ErrInvalidPasswordToken
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type CentralStats struct {
	InvalidSessionKeys    uint64
	ExpiredSessionKeys    uint64
	InvalidPasswords      uint64
	EmptyIdentities       uint64
	GoodOnceOffAuth       uint64
	GoodLogin             uint64
	Logout                uint64
	UserLoginAttempts     map[string]uint64
	userLoginAttemptsLock sync.Mutex
}

func isPowerOf2(x uint64) bool {
	return 0 == x&(x-1)
}

func (x *CentralStats) IncrementAndLog(name string, val *uint64, logger *log.Logger) {
	n := atomic.AddUint64(val, 1)
	if isPowerOf2(n) || (n&255) == 0 {
		logger.Infof("%v %v", n, name)
	}
}

func (x *CentralStats) IncrementInvalidPasswordHistory(logger *log.Logger, username string, clientIPAddress string) {
	x.userLoginAttemptsLock.Lock()
	defer x.userLoginAttemptsLock.Unlock()
	x.UserLoginAttempts[username]++
	count := x.UserLoginAttempts[username]
	if count < 5 || isPowerOf2(count) {
		logger.Infof("%v has %v invalid password attempts from %v", username, count, clientIPAddress)
	}
}

func (x *CentralStats) ResetInvalidPasswordHistory(logger *log.Logger, username string, clientIPAddress string) {
	x.userLoginAttemptsLock.Lock()
	defer x.userLoginAttemptsLock.Unlock()
	oldCount := x.UserLoginAttempts[username]
	if oldCount != 0 {
		x.UserLoginAttempts[username] = 0
		logger.Infof("Number of failed log in attempts for %v have been reset, (%v)", username, clientIPAddress)
	}
}

func (x *CentralStats) IncrementInvalidSessionKey(logger *log.Logger) {
	x.IncrementAndLog("invalid session keys", &x.InvalidSessionKeys, logger)
}

func (x *CentralStats) IncrementExpiredSessionKey(logger *log.Logger) {
	x.IncrementAndLog("expired session keys", &x.ExpiredSessionKeys, logger)
}

func (x *CentralStats) IncrementInvalidPasswords(logger *log.Logger) {
	x.IncrementAndLog("invalid passwords", &x.InvalidPasswords, logger)
}

func (x *CentralStats) IncrementEmptyIdentities(logger *log.Logger) {
	x.IncrementAndLog("empty identities", &x.EmptyIdentities, logger)
}

func (x *CentralStats) IncrementGoodOnceOffAuth(logger *log.Logger) {
	x.IncrementAndLog("good once-off auth", &x.GoodOnceOffAuth, logger)
}

func (x *CentralStats) IncrementGoodLogin(logger *log.Logger) {
	x.IncrementAndLog("good login", &x.GoodLogin, logger)
}

func (x *CentralStats) IncrementLogout(logger *log.Logger) {
	x.IncrementAndLog("logout", &x.Logout, logger)
}

type AuditActionType string

const (
	AuditActionAuthentication AuditActionType = "Login"
	AuditActionCreated                        = "Created"
	AuditActionUpdated                        = "Updated"
	AuditActionDeleted                        = "Deleted"
	AuditActionResetPassword                  = "Reset Password"
	AuditActionFailedLogin                    = "Failed Login"
	AuditActionUnlocked                       = "User Account Unlocked"
	AuditActionLocked                         = "User Account Locked"
	AuditActionRestored                       = "Restored"
)

type Auditor interface {
	AuditUserAction(identity, item, context string, auditActionType AuditActionType)
}

// LockingPolicy controls on a per-user basis, whether that user's account is automatically
// locked, after a set number of failed login attempts. It was created to disable the locking
// of special accounts, such as administrators or internal infrastructure accounts.
// This only applies if EnableAccountLocking is true
type LockingPolicy interface {
	IsLockable(identity string) (bool, error)
}

/*
For lack of a better name, this is the single hub of authentication that you interact with.
All public methods of Central are callable from multiple threads.
*/
type Central struct {
	// Stats must be first so that we are guaranteed to get it 8-byte aligned. We atomically
	// increment counters inside CentralStats, and the atomic functions need 8-byte alignment
	// on their operands.
	Stats                   CentralStats
	Auditor                 Auditor
	LockingPolicy           LockingPolicy
	Log                     *log.Logger
	MaxActiveSessions       int32
	NewSessionExpiresAfter  time.Duration
	DisablePasswordReuse    bool
	PasswordExpiresAfter    time.Duration
	UsersExemptFromExpiring []string
	MaxFailedLoginAttempts  int // only applies if EnableAccountLocking is true
	EnableAccountLocking    bool
	OAuth                   OAuth
	MSAAD                   MSAADInterface
	DB                      *sql.DB

	ldap                        LDAP
	userStore                   UserStore
	permitDB                    PermitDB
	sessionDB                   SessionDB
	roleGroupDB                 RoleGroupDB
	renameLock                  sync.Mutex
	loginDelayMS                uint64 // Number of milliseconds by which we increase the delay login every time the user enters invalid credentials
	shuttingDown                uint32
	syncMergeCount              int
	syncMergeInterval           time.Duration
	syncMergeTickerStopRequest  chan bool
	syncMergeTickerStopResponse chan bool
	syncMergeEnabled            bool
	msaadSyncMergeEnabled       bool
}

// Create a new Central object from the specified pieces.
// roleGroupDB may be nil
func NewCentral(logfile string, ldap LDAP, msaad MSAADInterface, userStore UserStore, permitDB PermitDB, sessionDB SessionDB, roleGroupDB RoleGroupDB) *Central {
	c := &Central{}

	if c.OAuth.Config.Providers != nil {
		c.OAuth.Initialize(c)
	}

	if ldap != nil {
		c.ldap = &sanitizingLDAP{
			backend: ldap,
		}
	}
	c.userStore = &sanitizingUserStore{
		backend: userStore,
	}
	c.permitDB = permitDB
	c.sessionDB = newCachedSessionDB(sessionDB)
	if roleGroupDB != nil {
		c.roleGroupDB = NewCachedRoleGroupDB(roleGroupDB)
	}
	c.MaxActiveSessions = 0
	c.NewSessionExpiresAfter = time.Duration(defaultSessionExpirySeconds) * time.Second
	c.Stats.UserLoginAttempts = make(map[string]uint64)

	// We don't want logging to stdout when the service is running on a windows
	// machine. This decision was made to avoid having to bloat the service with
	// unnecessary config
	c.Log = log.New(resolveLogfile(logfile), runtime.GOOS != "windows")
	if msaad != nil {
		c.MSAAD = msaad
		err := c.MSAAD.Initialize(c, c.Log)
		if err != nil {
			c.Log.Errorf("Error initializing MSAAD: %v", err)
			msaad = nil
		}
	}

	c.Log.Infof("Authaus successfully started up\n")

	return c
}

// Create a new 'Central' object from a Config.
func NewCentralFromConfig(config *Config) (central *Central, err error) {
	var (
		db          *sql.DB
		ldap        LDAP
		msaad       MSAADInterface
		userStore   UserStore
		permitDB    PermitDB
		sessionDB   SessionDB
		roleGroupDB RoleGroupDB
	)
	msaadUsed := config.MSAAD.ClientID != ""
	ldapUsed := len(config.LDAP.LdapHost) > 0

	// We don't want logging to stdout when the service is running on a windows machine
	startupLogger := log.New(resolveLogfile(config.Log.Filename), runtime.GOOS != "windows")

	defer func() {
		if ePanic := recover(); ePanic != nil {
			if ldap != nil {
				ldap.Close()
			}
			if userStore != nil {
				userStore.Close()
			}
			if permitDB != nil {
				permitDB.Close()
			}
			if sessionDB != nil {
				sessionDB.Close()
			}
			if roleGroupDB != nil {
				roleGroupDB.Close()
			}
			if db != nil {
				db.Close()
			}
			startupLogger.Errorf("Error initializing: %v\n", ePanic)
			err = ePanic.(error)
		}
	}()

	if config.SessionDB.MaxActiveSessions < 0 || config.SessionDB.MaxActiveSessions > 1 {
		panic(errors.New("MaxActiveSessions must be 0 or 1"))
	}

	if config.SessionDB.SessionExpirySeconds < 0 {
		panic(errors.New("SessionExpirySeconds must be 0 or more"))
	}

	// All of our interfaces which use a Postgres database share the same database, and thus the
	// same schema. So here we connect to that common SQL database that is used by all of them.
	// The original design of Authaus made all of these interfaces open to be implemented
	// by different units, and that is still possible. But it's just silly to open the same
	// database 4 times (which is what NewUserStoreDB_SQL et al used to do),
	// when we're actually just using a single shared DB.
	db, err = config.DB.Connect()
	if err != nil {
		panic(fmt.Errorf("Error connecting to DB: %v", err))
	}

	if ldapUsed {
		ldap = NewAuthenticator_LDAP(&config.LDAP)
	}

	if msaadUsed {
		msaad = &MSAAD{}
		msaadProvider := &MSAADProvider{
			tokenLock:      sync.Mutex{},
			tokenExpiresAt: time.Time{},
		}
		msaad.SetProvider(msaadProvider)
	}

	if userStore, err = NewUserStoreDB_SQL(db); err != nil {
		panic(fmt.Errorf("Error connecting to UserStoreDB: %v", err))
	}

	if permitDB, err = NewPermitDB_SQL(db); err != nil {
		panic(fmt.Errorf("Error connecting to PermitDB: %v", err))
	}

	if sessionDB, err = NewSessionDB_SQL(db); err != nil {
		panic(fmt.Errorf("Error connecting to SessionDB: %v", err))
	}

	if roleGroupDB, err = NewRoleGroupDB_SQL(db); err != nil {
		panic(fmt.Errorf("Error connecting to RoleGroupDB: %v", err))
	}
	oldPasswordHistorySize := config.UserStore.OldPasswordHistorySize
	if oldPasswordHistorySize == 0 {
		oldPasswordHistorySize = defaultOldPasswordHistorySize
	}
	userStore.SetConfig(time.Duration(config.UserStore.PasswordExpirySeconds)*time.Second, oldPasswordHistorySize, config.UserStore.UsersExemptFromExpiring)

	c := NewCentral(config.Log.Filename, ldap, msaad, userStore, permitDB, sessionDB, roleGroupDB)
	c.DB = db
	c.MaxActiveSessions = config.SessionDB.MaxActiveSessions
	if config.SessionDB.SessionExpirySeconds != 0 {
		c.NewSessionExpiresAfter = time.Duration(config.SessionDB.SessionExpirySeconds) * time.Second
	}
	startupLogger.Infof("Sessions expire after %v", c.NewSessionExpiresAfter)
	if config.UserStore.DisablePasswordReuse {
		c.DisablePasswordReuse = config.UserStore.DisablePasswordReuse
		startupLogger.Infof("Most recent %v passwords not allowed to be reused", oldPasswordHistorySize)
	} else if config.UserStore.OldPasswordHistorySize != 0 {
		startupLogger.Warnf("OldPasswordHistorySize of %v is specified, but DisablePasswordReuse is not. This limit of %v will have no effect.",
			config.UserStore.OldPasswordHistorySize, config.UserStore.OldPasswordHistorySize)
	}
	if config.MaxFailedLoginAttempts > 0 {
		c.MaxFailedLoginAttempts = config.MaxFailedLoginAttempts
	}
	if config.EnableAccountLocking {
		c.EnableAccountLocking = config.EnableAccountLocking
		startupLogger.Infof("Accounts are locked after %v failed login attempts", c.MaxFailedLoginAttempts)
	}
	if config.UserStore.PasswordExpirySeconds > 0 {
		c.PasswordExpiresAfter = time.Duration(config.UserStore.PasswordExpirySeconds) * time.Second
	}
	if c.PasswordExpiresAfter != 0 {
		startupLogger.Infof("Passwords expire after %v", c.PasswordExpiresAfter)
	}
	if len(config.UserStore.UsersExemptFromExpiring) > 0 {
		c.UsersExemptFromExpiring = config.UserStore.UsersExemptFromExpiring
	}
	c.msaadSyncMergeEnabled = msaadUsed
	if ldapUsed || msaadUsed {
		syncMergeSeconds := defaultSyncMergeTickerSeconds
		if ldapUsed && config.LDAP.LdapTickerTime > 0 {
			syncMergeSeconds = config.LDAP.LdapTickerTime
		}
		if msaadUsed && config.MSAAD.MergeIntervalSeconds > 0 {
			// If you have LDAP and MSAAD, then MSAAD wins. This seems like an arbitrary
			// distinction, because it's unlikely that you'll merge from both.
			// It would be nice to be able to emit a warning here, but we don't have a logger yet.
			// if config.MSAAD.MergeIntervalSeconds > 0 && config.LDAP.LdapTickerTime > 0 && config.MSAAD.MergeIntervalSeconds != config.LDAP.LdapTickerTime {
			// }
			syncMergeSeconds = config.MSAAD.MergeIntervalSeconds
		}
		c.syncMergeInterval = time.Duration(syncMergeSeconds) * time.Second
		c.StartMergeTicker()
	}

	c.OAuth.Config = config.OAuth
	if msaadUsed {
		c.MSAAD.SetConfig(config.MSAAD)
	}
	c.loginDelayMS = 500 // add 500 ms per invalid login attempt

	return c, nil
}

func resolveLogfile(logfile string) string {
	if logfile != "" {
		return logfile
	}
	return log.Stdout
}

// Set the size of the in-memory session cache
func (x *Central) SetSessionCacheSize(maxSessions int) {
	x.sessionDB.(*cachedSessionDB).MaxCachedSessions = maxSessions
}

// Pass in a session key that was generated with a call to Login(), and get back a token.
// A session key is typically a cookie.
func (x *Central) GetTokenFromSession(sessionkey string) (*Token, error) {
	if token, err := x.sessionDB.Read(sessionkey); err != nil {
		x.Stats.IncrementInvalidSessionKey(x.Log)
		return token, err
	} else {
		if time.Now().UnixNano() > token.Expires.UnixNano() {
			// DB has not yet expired token. It's OK for the DB to be a bit lazy in its cleanup.
			x.Stats.IncrementExpiredSessionKey(x.Log)
			return nil, ErrInvalidSessionToken
		} else {
			return token, err
		}
	}
}

func (x *Central) GetAllTokens(includeExpired bool) ([]*Token, error) {
	return x.sessionDB.GetAllTokens(includeExpired)
}

func (x *Central) GetAllOAuthTokenIDs() ([]string, error) {
	return x.sessionDB.GetAllOAuthTokenIDs()
}

// Perform a once-off authentication
func (x *Central) GetTokenFromIdentityPassword(identity, password string) (*Token, error) {
	// Treat empty identity specially, since this is a very common condition, and
	// tends to flood the logs.
	// Some day we may realize that it is better to emit the IP addresses here, even
	// for empty identity authorization requests.
	identity = strings.TrimSpace(identity)
	if identity == "" {
		x.Stats.IncrementEmptyIdentities(x.Log)
		return nil, ErrIdentityEmpty
	}
	user, eAuth := x.authenticate(identity, password, "")
	if eAuth == nil {
		if permit, ePermit := x.permitDB.GetPermit(user.UserId); ePermit == nil {
			t := &Token{
				Expires:      veryFarFuture,
				Identity:     user.getIdentity(),
				UserId:       user.UserId,
				Permit:       *permit,
				InternalUUID: user.InternalUUID,
			}
			x.Stats.IncrementGoodOnceOffAuth(x.Log)
			x.Log.Infof("Once-off auth successful (%v)", user.UserId)
			return t, nil
		} else {
			x.Log.Errorf("Once-off auth GetPermit failed (%v) (%v)", user.UserId, ePermit)
			return nil, ePermit
		}
	} else {
		x.Stats.IncrementInvalidPasswords(x.Log)
		x.Log.Errorf("Once-off auth Authentication failed (%v) (%v)", user.UserId, eAuth)
		return nil, eAuth
	}
}

// Authenticate the username + password, and if successful, call CreateSession()
func (x *Central) Login(username, password string, clientIPAddress string) (sessionkey string, token *Token, err error) {
	user, authErr := x.authenticate(username, password, clientIPAddress)
	if authErr != nil {
		err = authErr
		x.Log.Errorf("Login Authentication failed (%v) (%v)", username, err)
		return sessionkey, token, err
	}

	x.Stats.ResetInvalidPasswordHistory(x.Log, username, clientIPAddress)

	sessionkey, token, err = x.CreateSession(&user, clientIPAddress, "")
	if err == nil {
		x.Stats.IncrementGoodLogin(x.Log)
		x.Log.Infof("Login successful (%v)", user.UserId)
	}

	return
}

func (x *Central) ExemptFromExpiryCheck(username string) bool {
	for _, user := range x.UsersExemptFromExpiring {
		if user == username {
			return true
		}
	}
	return false
}

// CreateSession creates a new login session, after you have authenticated the caller
// Returns a session key, which can be used in future to retrieve the token.
// The internal session expiry is controlled with NewSessionExpiresAfter.
// The session key is typically sent to the client as a cookie.
// oauthSessionID is only applicable when this is an OAuth login.
func (x *Central) CreateSession(user *AuthUser, clientIPAddress, oauthSessionID string) (sessionkey string, token *Token, err error) {
	var permit *Permit
	if permit, err = x.permitDB.GetPermit(user.UserId); err != nil {
		x.Log.Errorf("Login GetPermit failed (%v) (%v)", user.UserId, err)
		return sessionkey, token, err
	}

	if x.MaxActiveSessions != 0 {
		if err = x.sessionDB.InvalidateSessionsForIdentity(user.UserId); err != nil {
			x.Log.Warnf("Invalidate sessions for identity (%v) failed when enforcing MaxActiveSessions (%v)", user.UserId, err)
			return sessionkey, token, err
		}
	}

	token = &Token{
		Identity:       user.getIdentity(),
		UserId:         user.UserId,
		Email:          user.Email,
		Username:       user.Username,
		InternalUUID:   user.InternalUUID,
		Permit:         *permit,
		OAuthSessionID: oauthSessionID,
	}

	sessionExpiry := time.Now().Add(x.NewSessionExpiresAfter)
	if x.PasswordExpiresAfter != 0 && user.Type != UserTypeLDAP && !x.ExemptFromExpiryCheck(user.Username) {
		userPasswordExpiry := user.PasswordModifiedDate.Add(x.PasswordExpiresAfter)
		if userPasswordExpiry.Before(sessionExpiry) {
			token.Expires = userPasswordExpiry
		} else {
			token.Expires = sessionExpiry
		}
	} else {
		token.Expires = sessionExpiry
	}

	sessionkey = generateSessionKey()
	if err = x.sessionDB.Write(sessionkey, token); err != nil {
		x.Log.Errorf("Writing session key failed (%v)", err)
		return sessionkey, token, err
	}
	return sessionkey, token, nil
}

// Authenticate the identity and password.
// Returns the userId of the user account, the identity of the user account, and an error if one occurred, else nil.
func (x *Central) authenticate(identity, password string, clientIPAddress string) (AuthUser, error) {
	user, err := x.userStore.GetUserFromIdentity(identity)
	if err != nil {
		if !errors.Is(err, ErrIdentityAuthNotFound) {
			err = fmt.Errorf("%v: %w", ErrIdentityAuthNotFound, err)
		}
		return AuthUser{}, err
	}
	var authTypeCheck AuthCheck
	if x.PasswordExpiresAfter != 0 {
		authTypeCheck = AuthCheckPasswordExpired
	} else {
		authTypeCheck = AuthCheckDefault
	}

	x.Stats.userLoginAttemptsLock.Lock()
	invalidPasswords := x.Stats.UserLoginAttempts[identity]
	x.Stats.userLoginAttemptsLock.Unlock()

	// Delay login with every failed log in attempt, cap the delay at 60 seconds
	if invalidPasswords > 0 {
		var loginDelay = x.loginDelayMS * invalidPasswords
		if loginDelay > 60000 {
			loginDelay = 60000
		}
		time.Sleep(time.Duration(loginDelay) * time.Millisecond)
	}

	var authErr error

	// We are consistent here with the behaviour of sqlSessionDB.Read, which prioritizes the LDAP identity
	// over the email address, as the return value of "identity".
	if user.Type == UserTypeLDAP && x.ldap != nil {
		err = x.ldap.Authenticate(user.Username, password)
		// We want to return Invalid Password or IdentityAuthNotFound, not Invalid Credentials
		// as LDAP doesnt differentiate between the 2
		authErr = err
		if err == ErrInvalidCredentials {
			// The user already exists on our system, which means it exists on LDAP due to our Merge, with
			// that knowledge we can say the password is invalid
			authErr = ErrInvalidPassword
		}
	} else {
		authErr = x.userStore.Authenticate(identity, password, authTypeCheck)
	}

	if authErr == ErrInvalidPassword {
		username := user.Username
		x.Stats.IncrementInvalidPasswords(x.Log)
		x.Stats.IncrementInvalidPasswordHistory(x.Log, username, clientIPAddress)
		if x.EnableAccountLocking {
			if isLockable, lockabilityErr := x.LockingPolicy.IsLockable(identity); lockabilityErr == nil {
				x.Stats.userLoginAttemptsLock.Lock()
				invalidPasswords = x.Stats.UserLoginAttempts[username]
				x.Stats.userLoginAttemptsLock.Unlock()
				if int(invalidPasswords) >= x.MaxFailedLoginAttempts && isLockable {
					if lockErr := x.userStore.LockAccount(user.UserId); lockErr == nil {
						contextData := userInfoToAuditTrailJSON(*user, clientIPAddress)
						x.Auditor.AuditUserAction(user.Username, "User Profile: "+user.Username, contextData, AuditActionLocked)
						authErr = ErrAccountLocked
					} else {
						authErr = lockErr
					}
				}

			} else {
				authErr = lockabilityErr
			}
		}
	}
	return *user, authErr
}

func (x *Central) AuthenticateUser(identity, password string, authTypeCheck AuthCheck) error {
	return x.userStore.Authenticate(identity, password, authTypeCheck)
}

// Merges ldap with user store every merge tick
func (x *Central) StartMergeTicker() error {
	x.Log.Info("Starting sync merge goroutine")
	if x.ldap != nil {
		x.Log.Info("LDAP sync merge enabled")
	}
	if x.msaadSyncMergeEnabled {
		x.Log.Info("MSAAD sync merge enabled")
	}
	x.syncMergeTickerStopRequest = make(chan bool)
	x.syncMergeTickerStopResponse = make(chan bool)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				x.Log.Errorf("MergeTick panic: %v", r)
			}
			x.Log.Info("Go routine for merge tick is stopping")
		}()
		x.MergeTick()
		for {
			select {
			case <-time.After(x.syncMergeInterval):
				x.MergeTick()
			case <-x.syncMergeTickerStopRequest:
				x.syncMergeTickerStopResponse <- true
				return
			}
		}
	}()

	return nil
}

func (x *Central) MergeTick() {
	defer func() {
		if r := recover(); r != nil {
			x.Log.Errorf("MergeTick panic: %v", r)
		}
	}()

	timeStart := time.Now()

	if x.ldap != nil {
		MergeLDAP(x)
	}
	if x.msaadSyncMergeEnabled {
		x.Log.Infof("Merge process starting...\n")
		if err := x.MSAAD.SynchronizeUsers(); err != nil {
			x.Log.Warnf("MSAAD synchronization failed: %v", err)
		}
	}

	timeComplete := time.Now()
	x.Log.Infof("Merge process duration: %.3f seconds", timeComplete.Sub(timeStart).Seconds())
	x.syncMergeCount++
}

func userInfoToAuditTrailJSON(user AuthUser, clientIPAddress string) string {
	type AuditDetail struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		UserId   int64  `json:"userid"`
		Email    string `json:"email"`
		Origin   string `json:"origin"`
	}
	auditDetail := AuditDetail{
		Service:  "auth",
		Username: user.Username,
		UserId:   int64(user.UserId),
		Email:    user.Email,
		Origin:   clientIPAddress,
	}
	contextData, _ := json.Marshal(auditDetail)
	return string(contextData)
}

func userInfoToJSON(user AuthUser) string {
	userJSON, _ := json.Marshal(user)
	return string(userJSON)
}

// Logout, which erases the session key
func (x *Central) Logout(sessionkey string) error {
	x.Stats.IncrementLogout(x.Log)
	return x.sessionDB.Delete(sessionkey)
}

// Invalidate all sessions for a particular identity
func (x *Central) InvalidateSessionsForIdentity(userId UserId) error {
	return x.sessionDB.InvalidateSessionsForIdentity(userId)
}

// GetPermit retrieves a Permit.
func (x *Central) GetPermit(userId UserId) (*Permit, error) {
	return x.permitDB.GetPermit(userId)
}

// GetPermits retrieves all Permits.
func (x *Central) GetPermits() (map[UserId]*Permit, error) {
	return x.permitDB.GetPermits()
}

// Change a Permit.
func (x *Central) SetPermit(userId UserId, permit *Permit) error {
	if err := x.permitDB.SetPermit(userId, permit); err != nil {
		x.Log.Errorf("SetPermit failed (%v) (%v)", userId, err)
		return err
	}
	x.Log.Infof("SetPermit successful (%v)", userId)
	return x.sessionDB.PermitChanged(userId, permit)
}

// Change a Password. This invalidates all sessions for this identity.
func (x *Central) SetPassword(userId UserId, password string) error {
	var enforceTypeCheck PasswordEnforcement
	if x.DisablePasswordReuse {
		enforceTypeCheck = PasswordEnforcementReuse
	} else {
		enforceTypeCheck = PasswordEnforcementDefault
	}
	if err := x.userStore.SetPassword(userId, password, enforceTypeCheck); err != nil {
		x.Log.Errorf("SetPassword failed (%v) (%v)", userId, password)
		return err
	}
	x.Log.Infof("SetPassword successful (%v)", userId)
	return x.sessionDB.InvalidateSessionsForIdentity(userId)
}

// Create a one-time token that can be used to reset the password with a subsequent call to ResetPasswordFinish.
// Any subsequent call to ResetPasswordStart causes the current token to be invalidated, so there can only
// be a single active token. The token is valid until the time specified by 'expires'.
func (x *Central) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	token, err := x.userStore.ResetPasswordStart(userId, expires)
	if err != nil {
		x.Log.Errorf("ResetPasswordStart failed (%v) (%v)", userId, err)
		return "", err
	}
	x.Log.Infof("ResetPasswordStart successful (%v)", userId)
	return token, err
}

// Complete the password reset process, by providing a token that was generated by ResetPasswordStart.
// If this succeeds, then the password is set to 'password', and the token becomes invalid.
func (x *Central) ResetPasswordFinish(userId UserId, token string, password string) error {
	var enforceTypeCheck PasswordEnforcement
	if x.DisablePasswordReuse {
		enforceTypeCheck = PasswordEnforcementReuse
	} else {
		enforceTypeCheck = PasswordEnforcementDefault
	}
	if err := x.userStore.ResetPasswordFinish(userId, token, password, enforceTypeCheck); err != nil {
		x.Log.Errorf("ResetPasswordFinish failed (%v) (%v)", userId, err)
		return err
	}
	x.Log.Infof("ResetPasswordFinish successful (%v)", userId)
	x.sessionDB.InvalidateSessionsForIdentity(userId)
	return nil
}

// Create an identity in the AuthUserStore.
func (x *Central) CreateUserStoreIdentity(user *AuthUser, password string) (UserId, error) {
	userId, e := x.userStore.CreateIdentity(user, password)
	if e == nil {
		x.Log.Infof("CreateAuthenticatorIdentity successful: (%v)", userId)
	} else {
		x.Log.Warnf("CreateAuthenticatorIdentity failed: (%v), (%v)", userId, e)
	}
	return userId, e
}

// Update a user in the AuthUserStore.
func (x *Central) UpdateIdentity(user *AuthUser) error {
	e := x.userStore.UpdateIdentity(user)
	if e != nil {
		x.Log.Errorf("Update Identity failed (%v) (%v)", user.UserId, e)
		return e
	}

	x.Log.Infof("Update Identity successful (%v)", user.UserId)
	return nil
}

// Unlock user in the AuthUserStore.
func (x *Central) UnlockAccount(userId UserId) error {
	e := x.userStore.UnlockAccount(userId)
	if e != nil {
		x.Log.Warnf("Failed to unlock user (%v) (%v)", userId, e)
		return e
	}

	user, eUser := x.GetUserFromUserId(userId)
	if eUser != nil {
		return eUser
	}
	x.Stats.ResetInvalidPasswordHistory(x.Log, user.Username, "")
	x.Log.Infof("Unlocked user (%v)", userId)
	return nil
}

// Archive a user in the AuthUserStore.
func (x *Central) ArchiveIdentity(userId UserId) error {
	e := x.userStore.ArchiveIdentity(userId)
	if e != nil {
		x.Log.Warnf("Archive Identity failed: (%v), (%v)", userId, e)
		return e
	}
	e = x.InvalidateSessionsForIdentity(userId)
	if e != nil {
		x.Log.Warnf("Archive Identity failed, error invalidating sessions (%v) (%v)", userId, e)
		return e
	}
	return nil
}

func (x *Central) UnArchiveIdentity(userId UserId) error {
	e := x.userStore.UnarchiveIdentity(userId)
	if e != nil {
		x.Log.Warnf("Unarchive Identity failed: (%v), (%v)", userId, e)
		return e
	}
	e = x.InvalidateSessionsForIdentity(userId)
	if e != nil {
		x.Log.Warnf("Archive Identity failed, error invalidating sessions (%v) (%v)", userId, e)
		return e
	}
	return nil
}

// GetUserFromIdentity gets AuthUser object from either an email address or a username.
func (x *Central) GetUserFromIdentity(identity string) (AuthUser, error) {
	user, e := x.userStore.GetUserFromIdentity(identity)
	if e == nil {
		return *user, nil
	} else {
		x.Log.Errorf("GetUserIdFromIdentity failed (%v) (%v)", identity, e)
	}
	return AuthUser{}, e
}

// GetUserFromUserId gets AuthUser object from userid.
func (x *Central) GetUserFromUserId(userId UserId) (AuthUser, error) {
	user, e := x.userStore.GetUserFromUserId(userId)
	if e == nil {
		return *user, nil
	} else {
		x.Log.Errorf("GetIdentityFromUserId failed (%v) (%v)", userId, e)
	}
	return AuthUser{}, e
}

// GetUserNameFromUserId gets AuthUser full name from userid.
func (x *Central) GetUserNameFromUserId(userId UserId) string {
	switch userId {
	case UserIdAdministrator:
		return "Administrator"
	case UserIdLDAPMerge:
		return "LDAP Merge"
	case UserIdOAuthImplicitCreate:
		return "OAuth Sign-in"
	case UserIdMSAADMerge:
		return "MSAAD Merge"
	}
	user, e := x.userStore.GetUserFromUserId(userId)
	if e == nil {
		return user.Firstname + " " + user.Lastname
	} else {
		x.Log.Errorf("GetIdentityFromUserId failed (%v) (%v)", userId, e)
	}
	return ""
}

// Rename an identity. Invalidates all existing sessions for that identity
func (x *Central) RenameIdentity(oldIdent, newIdent string) error {
	// Since our rename involves two distinct ops that we can't unify into a single atomic
	// operation, we ensure that renames are serialized.
	x.renameLock.Lock()
	defer x.renameLock.Unlock()

	oldIdent = CanonicalizeIdentity(oldIdent)
	newIdent = CanonicalizeIdentity(newIdent)
	if oldIdent == newIdent {
		// This just doesn't make sense, and it has the potential to violate assumptions by other pieces of code down below, so we silently allow it
		x.Log.Infof("RenameIdentity succeeded (%v -> %v) (no action taken)", oldIdent, newIdent)
		return nil
	}

	user, eGetUserId := x.userStore.GetUserFromIdentity(oldIdent)
	if eGetUserId != nil {
		x.Log.Infof("Could not find userId for identity (%v) (%v)", oldIdent, ErrIdentityAuthNotFound)
		return ErrIdentityAuthNotFound
	}

	if err := x.userStore.RenameIdentity(oldIdent, newIdent); err != nil {
		x.Log.Errorf("RenameIdentity failed (%v -> %v) (%v)", oldIdent, newIdent, err)
		return err
	}

	x.Log.Infof("RenameIdentity (UserStore) successful (%v -> %v)", oldIdent, newIdent)

	eInvalidate := x.InvalidateSessionsForIdentity(user.UserId)
	x.Log.Infof("RenameIdentity (%v -> %v), session invalidation result (%v) for (%v)", oldIdent, newIdent, eInvalidate, user.UserId)
	return nil
}

type dataSlice []*data

type data struct {
	count int64
	size  int64
}

// GetAuthenticatorIdentities retrieves all identities known to the Authenticator.
func (x *Central) GetAuthenticatorIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) {
	return x.userStore.GetIdentities(getIdentitiesFlag)
}

// GetRoleGroupDB retrieves the Role Group Database (which may be nil)
func (x *Central) GetRoleGroupDB() RoleGroupDB {
	return x.roleGroupDB
}

func (x *Central) RemoveGroupFromAllUsers(groupIDString string) error {
	gID, err := strconv.ParseUint(groupIDString, 10, 32)
	if err != nil {
		return err
	}
	groupID := GroupIDU32(gID)

	users, err := x.GetAuthenticatorIdentities(GetIdentitiesFlagDeleted)
	if err != nil {
		return err
	}

	for _, user := range users {
		perm, err := x.GetPermit(user.UserId)
		if err != nil {
			continue
		}

		groups, err := DecodePermit(perm.Roles)
		if err != nil {
			return err
		}

		// Remove the group from the list of groups
		modified := false
		for i, g := range groups {
			if g == groupID {
				groups = append(groups[:i], groups[i+1:]...)
				modified = true
			}
		}

		// Encode the permit
		if modified {
			perm.Roles = EncodePermit(groups)
			x.Log.Infof("Removing group %v: setting permit for %v\n", groupID, user.Email)

			//Set the permit
			err = x.SetPermit(user.UserId, perm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (x *Central) IsShuttingDown() bool {
	return atomic.LoadUint32(&x.shuttingDown) != 0
}

func (x *Central) Close() {
	if x.Log != nil {
		x.Log.Infof("Authaus has started shutting down")
	}
	atomic.StoreUint32(&x.shuttingDown, 1)
	if x.syncMergeEnabled {
		x.syncMergeTickerStopRequest <- true
		<-x.syncMergeTickerStopResponse
	}
	if x.ldap != nil {
		x.ldap.Close()
		x.ldap = nil
	}
	if x.userStore != nil {
		x.userStore.Close()
		x.userStore = nil
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
	if x.DB != nil {
		x.DB.Close()
	}
	if x.Log != nil {
		x.Log.Infof("Authaus has shut down")
		// Don't set Log to nil, because a background/cleanup goroutine can't be expected to
		// check for x.Log being nil every time before it emits a log message.
	}
}

func (x *Central) debugEnableSessionDB(enable bool) {
	// Used for testing the session cache
	x.sessionDB.(*cachedSessionDB).enableDB = enable
}
