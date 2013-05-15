package authaus

import (
	"fmt"
	"github.com/mmitton/ldap"
)

type LdapConnectionMode int

const (
	LdapConnectionModePlainText LdapConnectionMode = iota
	LdapConnectionModeSSL                          = iota
	LdapConnectionModeTLS                          = iota
)

type ldapAuthenticator struct {
	con *ldap.Conn
}

func (x *ldapAuthenticator) Authenticate(identity, password string) error {
	if len(password) == 0 {
		// Many LDAP servers (or AD) will allow an anonymous BIND.
		// I've never seen the need for a password-less user authenticated against LDAP.
		return ErrInvalidPassword
	}
	err := x.con.Bind(identity, password)
	if err != nil {
		return NewError(ErrIdentityAuthNotFound, err.Error())
	}
	return nil
}

func (x *ldapAuthenticator) SetPassword(identity, password string) error {
	return ErrUnsupported
}

func (x *ldapAuthenticator) Close() {
	if x.con != nil {
		x.con.Close()
		x.con = nil
	}
}

func NewAuthenticator_LDAP(mode LdapConnectionMode, network, addr string) (Authenticator, error) {
	var err error
	auth := &ldapAuthenticator{}
	switch mode {
	case LdapConnectionModePlainText:
		auth.con, err = ldap.Dial(network, addr)
		break
	case LdapConnectionModeSSL:
		auth.con, err = ldap.DialSSL(network, addr)
		break
	case LdapConnectionModeTLS:
		auth.con, err = ldap.DialTLS(network, addr)
		break
	}
	if err != nil {
		fmt.Printf("LDAP new. error = '%v'\n", err)
		return nil, NewError(ErrConnect, err.Error())
	}
	return auth, nil
}
