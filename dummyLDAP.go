package authaus

import (
	"sync"
)

type dummyLdapUser struct {
	username     string
	email        string
	firstname    string
	lastname     string
	mobilenumber string
	password     string
}

type dummyLdap struct {
	ldapUsers []*dummyLdapUser
	usersLock sync.RWMutex
}

func (x *dummyLdap) Authenticate(identity, password string) (er error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	user := x.getLdapUser(identity)
	if user == nil {
		er = ErrInvalidCredentials
	} else if len(password) == 0 {
		er = ErrInvalidPassword
	} else if user.password == password {
		er = nil
	} else {
		er = ErrInvalidCredentials
	}

	return
}

func (x *dummyLdap) GetLdapUsers() ([]AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	//Now we build up and return the list of ldap users ([]AuthUsers)
	ldapUsers := make([]AuthUser, 0)
	for _, ldapUser := range x.ldapUsers {
		ldapUsers = append(ldapUsers, AuthUser{UserId: NullUserId, Email: ldapUser.email, Username: ldapUser.username, Firstname: ldapUser.firstname, Lastname: ldapUser.lastname, Mobilenumber: ldapUser.mobilenumber, Type: UserTypeLDAP})
	}
	return ldapUsers, nil
}

func (x *dummyLdap) getLdapUser(identity string) *dummyLdapUser {
	for _, v := range x.ldapUsers {
		if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) {
			return v
		}
	}
	return nil
}

func (x *dummyLdap) AddLdapUser(username, password, email, name, surname, mobile string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	user := dummyLdapUser{
		username:     username,
		email:        email,
		firstname:    name,
		lastname:     surname,
		mobilenumber: mobile,
		password:     password,
	}
	x.ldapUsers = append(x.ldapUsers, &user)
}

func (x *dummyLdap) UpdateLdapUser(username, email, name, surname, mobile string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	for _, ldapUser := range x.ldapUsers {
		if ldapUser.username == username {
			ldapUser.email = email
			ldapUser.firstname = name
			ldapUser.lastname = surname
			ldapUser.mobilenumber = mobile
		}
	}
}

func (x *dummyLdap) RemoveLdapUser(username string) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	for i, ldapUser := range x.ldapUsers {
		if ldapUser.username == username {
			x.ldapUsers = append(x.ldapUsers[:i], x.ldapUsers[i+1:]...)
			break
		}
	}
}

func (x *dummyLdap) Close() {
	//Set incrementing user id to 0, for unit test prediction
	nextUserId = 0
}
