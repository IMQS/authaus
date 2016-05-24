package authaus

import (
	//"github.com/mmitton/ldap"
	"database/sql"
	"errors"
	"fmt"
	"github.com/mavricknz/ldap"
	"time"
"strings"
)

type LdapConnectionMode int

const (
	LdapConnectionModePlainText LdapConnectionMode = iota
	LdapConnectionModeSSL                          = iota
	LdapConnectionModeTLS                          = iota
)

type LdapImpl struct {
	db     *sql.DB
	config *ConfigLDAP
}

func (x *LdapImpl) Authenticate(identity, password string) (er error) {
	if len(password) == 0 {
		// Many LDAP servers (or AD) will allow an anonymous BIND.
		// I've never seen the need for a password-less user authenticated against LDAP.
		er = ErrInvalidPassword
		return
	}

	con, err := NewLDAPConnect(x.config)
	if err != nil {
		return err
	}
	defer con.Close()
	err = con.Bind(fmt.Sprintf(`%v@%v`, identity, x.config.LdapDomain), password)
	if err != nil {
		if strings.Index(err.Error(), "Invalid Credentials") != 0 {
			er = NewError(ErrInvalidCredentials, err.Error())
		} else {
			err = er
		}
	}

	return
}

func (x *LdapImpl) Close() {

}

func (x *LdapImpl) GetLdapUsers() ([]AuthUser, error) {
	var attributes []string = []string{
		"sAMAccountName",
		"cn",
		"name",
		"sn",
		"mail",
		"mobile"}

	searchRequest := ldap.NewSearchRequest(
		"dc=imqs,dc=local",
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		"(objectclass=user)",
		attributes,
		nil)

	con, err := NewLDAPConnectAndBind(x.config)
	if err != nil {
		return nil, err
	}
	defer con.Close()
	sr, err := con.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	getAttributeValue := func(entry ldap.Entry, attribute string) string {
		values := entry.GetAttributeValues(attribute)
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	ldapUsers := make([]AuthUser, len(sr.Entries))
	for i, value := range sr.Entries {
		username := getAttributeValue(*value, "sAMAccountName")
		name := getAttributeValue(*value, "cn")
		surname := getAttributeValue(*value, "sn")
		email := getAttributeValue(*value, "mail")
		mobile := getAttributeValue(*value, "mobile")
		ldapUsers[i] = AuthUser{UserId: NullUserId, Email: email, Username: username, Firstname: name, Lastname: surname, Mobilenumber: mobile}
	}
	return ldapUsers, nil
}

func NewLDAPConnectAndBind(config *ConfigLDAP) (*ldap.LDAPConnection, error) {
	con, err := NewLDAPConnect(config)
	if err != nil {
		return nil, err
	}
	if err := con.Bind(config.LdapUsername, config.LdapPassword); err != nil {
		return nil, err
	}
	return con, nil
}

func NewLDAPConnect(config *ConfigLDAP) (*ldap.LDAPConnection, error) {
	//fmt.Printf("Connect: Username: %v, Password: %v, Host: %v, Port: %v, Encryption: %v, Domain: %v", config.LdapUsername, config.LdapPassword, config.LdapHost, config.LdapPort, config.Encryption, config.LdapDomain)
	con := ldap.NewLDAPConnection(config.LdapHost, config.LdapPort)
	con.NetworkConnectTimeout = 5 * time.Second
	con.ReadTimeout = 5 * time.Second
	ldapMode, legalLdapMode := configLdapNameToMode[config.Encryption]
	if !legalLdapMode {
		return nil, errors.New(fmt.Sprintf("Unknown ldap mode %v. Recognized modes are TLS, SSL, and empty for unencrypted", config.Encryption))
	}
	switch ldapMode {
	case LdapConnectionModePlainText:
	case LdapConnectionModeSSL:
		con.IsSSL = true
	case LdapConnectionModeTLS:
		con.IsTLS = true
	}
	if err := con.Connect(); err != nil {
		con.Close()
		return nil, err
	}
	return con, nil
}

func NewAuthenticator_LDAP(config *ConfigLDAP) (*LdapImpl, error) {
	ldap := &LdapImpl{}
	ldap.config = config
	return ldap, nil
}
