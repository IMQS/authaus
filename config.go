package authaus

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"io/ioutil"
	"os"
	"strconv"
)

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
	"Authenticator": {
		"Type":			"ldap",
		"LdapHost":		"domaincontroller.example.com",
		"LdapPort":		389,
		"Encryption":	"ssl"
	},
	"PermitDB": {
		"DB": {
			"Driver":		"postgres",
			"Host":			"auth.example.com",
			"Port":			5432,
			"Database": 	"auth",
			"User":			"jim",
			"Password":		"123",
			"SSL":			true
		}
	},
	"SessionDB": {
		"MaxActiveSessions": 0,
		"SessionExpirySeconds": 2592000,
		"DB": {
			"Driver":		"postgres",
			"Host":			"auth.example.com",
			"Port":			5432,
			"Database": 	"auth",
			"User":			"jim",
			"Password":		"123",
			"SSL":			true
		}
	},
	"RoleGroupDB": {
		"DB": {
			"Driver":		"postgres",
			"Host":			"auth.example.com",
			"Port":			5432,
			"Database": 	"auth",
			"User":			"jim",
			"Password":		"123",
			"SSL":			true
		}
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
	sslmode := "disable"
	if x.SSL {
		sslmode = "require"
	}
	conStr := fmt.Sprintf("host=%v user=%v password=%v dbname=%v sslmode=%v", x.Host, x.User, x.Password, x.Database, sslmode)
	if x.Port != 0 {
		conStr += fmt.Sprintf(" port=%v", x.Port)
	}

	return sql.Open(x.Driver, conStr)
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
	Port         int
	Bind         string
}

type ConfigLog struct {
	Filename string
}

type ConfigPermitDB struct {
	DB DBConnection
}

type ConfigSessionDB struct {
	DB                   DBConnection
	MaxActiveSessions    int32 // Maximum number of active sessions per user. legal values are 0 and 1. Zero means unlimited.
	SessionExpirySeconds int64 // Lifetime of newly created sessions, in seconds. Zero means default, which is defaultSessionExpirySeconds (30 days)
}

type ConfigRoleGroupDB struct {
	DB DBConnection
}

type ConfigAuthenticator struct {
	Type       string // "ldap", "db"
	LdapHost   string //
	LdapPort   int32  //
	Encryption string // "", "TLS", "SSL"
	DB         DBConnection
}

type ConfigUserStoreDB struct {
	DB DBConnection
}

/*
Configuration information. This is typically loaded from a .json config file.
*/
type Config struct {
	Log           ConfigLog
	HTTP          ConfigHTTP
	PermitDB      ConfigPermitDB
	SessionDB     ConfigSessionDB
	RoleGroupDB   ConfigRoleGroupDB
	Authenticator ConfigAuthenticator
	UserStore     ConfigUserStoreDB
}

func (x *Config) Reset() {
	*x = Config{}
	x.HTTP.CookieName = "session"
	x.HTTP.Bind = "127.0.0.1"
	x.HTTP.Port = 8080
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
