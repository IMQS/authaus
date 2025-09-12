package authaus

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

// ClientSecretExpiryNotificationFunc is a callback function type for client secret expiry notifications.
// It's called when a client secret is about to expire within the configured threshold.
// Parameters:
//   - providerName: Name of the OAuth provider or "MSAAD" for MSAAD configuration
//   - daysUntilExpiry: Number of days until the secret expires
//   - expiryDate: The actual expiry date of the secret
type ClientSecretExpiryNotificationFunc func(providerName string, daysUntilExpiry int, expiryDate time.Time)

/*

Full populated config:

{
	"Log": {
		"Filename":		"/var/log/authaus/authaus.log"		// This can also be 'stdout' or 'stderr'. 'stdout' is the default, if unspecified.
	},
	"HTTP": {
		"CookieName":	"session",
		"CookieSecure":	true,
		"Port":			8080,
		"Bind":			"127.0.0.1"
	},
	"DB": {
		"Driver":		"postgres",
		"Host":			"auth.example.com",
		"Port":			5432,
		"Database": 	"auth",
		"User":			"jim",
		"Password":		"123",
		"SSL":			true
	},
	"LDAP": {
		"LdapHost":		"example.local",
		"LdapPort":		389,
		"Encryption":	"",
		"LdapUsername":	"joe@example.local",
		"LdapPassword":	"1234abcd",
		"LdapDomain":	"example.local",
		"LdapTickerTime": 300 // Seconds,
		"BaseDN":        "dc=exmaple1,dc=example2",
		"SysAdminEmail":  "joeAdmin@example.com",
		"LdapSearchFilter": "(&(objectCategory=person)(objectClass=user))"
	},
	"OAuth": {
		"Verbose": false,
		"Providers": {
			"eMerge": {
				"Type": "msaad",
				"Title": "Hooli",
				"LoginURL": "https://login.microsoftonline.com/{your tenant id here}/oauth2/v2.0/authorize",
				"TokenURL": "https://login.microsoftonline.com/{your tenant id here}/oauth2/v2.0/token",
				"RedirectURL": "https://mysite.example.com/auth/oauth/finish",
				"ClientID": "your client UUID here",
				"Scope": "openid email offline_access",
				"ClientSecret": "your secret here",
				"ClientSecretExpiryDate": "2024-12-31T23:59:59Z"
			}
		},
		"SecretExpiryNotificationDays": 14,
		"SecretExpiryCheckIntervalHours": 1
	},
	"MSAAD": {
		"ClientID": "your client UUID",
		"ClientSecret": "your secret",
		"ClientSecretExpiryDate": "2024-12-31T23:59:59Z"
	},
	"SessionDB": {
		"MaxActiveSessions": 0,
		"SessionExpirySeconds": 2592000,
	}
}

*/

var configLdapNameToMode = map[string]LdapConnectionMode{
	"":    LdapConnectionModePlainText,
	"SSL": LdapConnectionModeSSL,
	"TLS": LdapConnectionModeTLS,
}

// Database connection information
type DBConnection struct {
	Driver   string
	Host     string
	Port     uint16
	Database string
	User     string
	Password string
	SSL      bool
	// If you add more fields, remember to change Equals() as well as signature()
}

func (x *DBConnection) Connect() (*sql.DB, error) {
	return sql.Open(x.Driver, x.ConnectionString())
}

func (x *DBConnection) Equals(y *DBConnection) bool {
	return x.Driver == y.Driver &&
		x.Host == y.Host &&
		x.Port == y.Port &&
		x.Database == y.Database &&
		x.User == y.User &&
		x.Password == y.Password &&
		x.SSL == y.SSL
}

func (x *DBConnection) ConnectionString() string {
	sslmode := "disable"
	if x.SSL {
		sslmode = "require"
	}
	conStr := fmt.Sprintf("host=%v user=%v password=%v dbname=%v sslmode=%v", x.Host, x.User, x.Password, x.Database, sslmode)
	if x.Port != 0 {
		conStr += fmt.Sprintf(" port=%v", x.Port)
	}
	return conStr
}

// Return a concatenation of all struct fields
func (x *DBConnection) signature() string {
	return x.Driver + " " +
		x.Host + " " +
		strconv.FormatInt(int64(x.Port), 10) + " " +
		x.Database + " " +
		x.User + " " +
		x.Password + " " +
		strconv.FormatBool(x.SSL)
}

type ConfigHTTP struct {
	CookieName   string
	CookieSecure bool
	Port         string
	Bind         string
}

type ConfigLog struct {
	Filename string
}

type ConfigSessionDB struct {
	MaxActiveSessions    int32 // Maximum number of active sessions per user. legal values are 0 and 1. Zero means unlimited.
	SessionExpirySeconds int64 // Lifetime of newly created sessions, in seconds. Zero means default, which is defaultSessionExpirySeconds (30 days)
}

type ConfigLDAP struct {
	LdapHost           string //
	LdapPort           uint16 //
	Encryption         string // "", "TLS", "SSL"
	LdapUsername       string //
	LdapPassword       string //
	LdapDomain         string //
	LdapTickerTime     int    // seconds
	BaseDN             string //
	SysAdminEmail      string //
	LdapSearchFilter   string
	InsecureSkipVerify bool // If true, then skip SSL verification. Only applicable when Encryption = SSL
	DebugUserPull      bool // If true, prints out the result of every LDAP user pull
}

type ConfigUserStoreDB struct {
	DisablePasswordReuse    bool
	OldPasswordHistorySize  int // When DisablePasswordReuse is true, this is how far back in history we look (i.e. number of password changes), to determine if a password has been used before
	PasswordExpirySeconds   int
	UsersExemptFromExpiring []string // List of users that are not subject to password expiry. Username will be used for comparison.
}

/*
Configuration information. This is typically loaded from a .json config file.
*/
type Config struct {
	DB                     DBConnection
	Log                    ConfigLog
	HTTP                   ConfigHTTP
	SessionDB              ConfigSessionDB
	LDAP                   ConfigLDAP
	UserStore              ConfigUserStoreDB
	OAuth                  ConfigOAuth
	MSAAD                  ConfigMSAAD
	AuditServiceUrl        string
	EnableAccountLocking   bool
	MaxFailedLoginAttempts int
}

func (x *Config) Reset() {
	*x = Config{}
	x.HTTP.CookieName = "session"
	x.HTTP.Bind = "127.0.0.1"
	x.HTTP.Port = "8080"
}

func (x *Config) LoadFile(filename string) error {
	x.Reset()
	var file *os.File
	var all []byte
	var err error
	if file, err = os.Open(filename); err != nil {
		return err
	}
	defer file.Close()
	if all, err = ioutil.ReadAll(file); err != nil {
		return err
	}
	if err = json.Unmarshal(all, x); err != nil {
		return err
	}
	return nil
}
