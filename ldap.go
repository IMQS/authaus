package authaus

import (
	"fmt"
	//"github.com/mmitton/ldap"
	"github.com/mavricknz/ldap"
	"time"
)

type LdapConnectionMode int

const (
	LdapConnectionModePlainText LdapConnectionMode = iota
	LdapConnectionModeSSL                          = iota
	LdapConnectionModeTLS                          = iota
)

type ldapAuthenticator struct {
	//con *ldap.Conn
	con *ldap.LDAPConnection
}

func (x *ldapAuthenticator) Authenticate(identity, password string) (er error) {
	if len(password) == 0 {
		// Many LDAP servers (or AD) will allow an anonymous BIND.
		// I've never seen the need for a password-less user authenticated against LDAP.
		er = ErrInvalidPassword
		return
	}
	err := x.con.Bind(identity, password)
	if err != nil {
		er = NewError(ErrIdentityAuthNotFound, err.Error())
	}
	return
}

func (x *ldapAuthenticator) Close() {
	if x.con != nil {
		x.con.Close()
		x.con = nil
	}
}

type ldapUserStore struct {
	//con *ldap.Conn
	con *ldap.LDAPConnection
}

func (x *ldapUserStore) SetPassword(identity, password string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) ResetPasswordStart(identity string, expires time.Time) (string, error) {
	return "", ErrUnsupported
}

func (x *ldapUserStore) ResetPasswordFinish(identity string, token string, password string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) CreateIdentity(identity, password string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) RenameIdentity(oldIdent, newIdent string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) GetIdentities() ([]string, error) {
	return []string{}, ErrUnsupported
}

func (x *ldapUserStore) Close() {
	if x.con != nil {
		x.con.Close()
		x.con = nil
	}
}

func NewAuthenticator_LDAP(mode LdapConnectionMode, host string, port uint16) (Authenticator, error) {
	//var err error
	con := ldap.NewLDAPConnection(host, port)
	switch mode {
	case LdapConnectionModePlainText:
		//auth.con, err = ldap.Dial(network, addr)
	case LdapConnectionModeSSL:
		con.IsSSL = true
		//auth.con, err = ldap.DialSSL(network, addr)
	case LdapConnectionModeTLS:
		con.IsTLS = true
		//auth.con, err = ldap.DialTLS(network, addr)
	}
	if err := con.Connect(); err != nil {
		fmt.Printf("LDAP new. error = '%v'\n", err)
		con.Close()
		return nil, NewError(ErrConnect, err.Error())
	}
	auth := &ldapAuthenticator{}
	auth.con = con
	return auth, nil
}
