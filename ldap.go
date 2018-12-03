package authaus

import (
	//"github.com/mmitton/ldap"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mavricknz/ldap"
)

type LdapConnectionMode int

const (
	LdapConnectionModePlainText LdapConnectionMode = iota
	LdapConnectionModeSSL                          = iota
	LdapConnectionModeTLS                          = iota
)

type LdapImpl struct {
	config *ConfigLDAP
}

func (x *LdapImpl) Authenticate(identity, password string) error {
	if len(password) == 0 {
		// Many LDAP servers (or AD) will allow an anonymous BIND.
		// I've never seen the need for a password-less user authenticated against LDAP.
		return ErrInvalidPassword
	}

	con, err := NewLDAPConnect(x.config)
	if err != nil {
		return err
	}
	defer con.Close()
	// We need to know whether or not we must add the domain to the identity by checking if it contains '@'
	if !strings.Contains(identity, "@") {
		identity = fmt.Sprintf(`%v@%v`, identity, x.config.LdapDomain)
	}
	err = con.Bind(identity, password)
	if err != nil {
		if strings.Index(err.Error(), "Invalid Credentials") != 0 {
			return ErrInvalidCredentials
		} else {
			return err
		}
	}
	return nil
}

func (x *LdapImpl) Close() {

}

func (x *LdapImpl) GetLdapUsers() ([]AuthUser, error) {
	var attributes []string = []string{
		"sAMAccountName",
		"givenName",
		"name",
		"sn",
		"mail",
		"mobile"}

	searchRequest := ldap.NewSearchRequest(
		x.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		x.config.LdapSearchFilter,
		attributes,
		nil)

	con, err := NewLDAPConnectAndBind(x.config)
	if err != nil {
		return nil, err
	}
	defer con.Close()
	sr, err := con.SearchWithPaging(searchRequest, 100)
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
		name := getAttributeValue(*value, "givenName")
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
	con := ldap.NewLDAPConnection(config.LdapHost, config.LdapPort)
	con.NetworkConnectTimeout = 30 * time.Second
	con.ReadTimeout = 30 * time.Second
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

func NewAuthenticator_LDAP(config *ConfigLDAP) *LdapImpl {
	return &LdapImpl{
		config: config,
	}
}
