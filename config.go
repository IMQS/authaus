package authaus

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

/*

Example config:

{
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
		"DBConnection": {
			"Host":			"auth.example.com",
			"Database": 	"auth",
			"User":			"jim",
			"Password":		"123",
			"SSL":			true
		}
	},
	"SessionDB": {
		"DBConnection": {
			"Host":			"auth.example.com",
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

type ConfigDBConnection struct {
	Host     string
	Database string
	User     string
	Password string
	SSL      bool
}

type ConfigHTTP struct {
	CookieName   string
	CookieSecure bool
	Port         int
	Bind         string
}

type ConfigPermitDB struct {
	DBConnection ConfigDBConnection
}

type ConfigSessionDB struct {
	DBConnection ConfigDBConnection
}

type ConfigAuthenticator struct {
	Type       string // "ldap"
	LdapHost   string // 
	LdapPort   int32  // 
	Encryption string // "", "TLS", "SSL"
}

type Config struct {
	HTTP          ConfigHTTP
	PermitDB      ConfigPermitDB
	SessionDB     ConfigSessionDB
	Authenticator ConfigAuthenticator
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
	if all, err = ioutil.ReadAll(file); err != nil {
		return err
	}
	if err = json.Unmarshal(all, x); err != nil {
		return err
	}
	return nil
}
