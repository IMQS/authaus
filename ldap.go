package authaus

import (
	"fmt"
	//"github.com/mmitton/ldap"
	"database/sql"
	"github.com/mavricknz/ldap"
	"strings"
	"sync"
	"time"
)

type LdapConnectionMode int

const (
	LdapConnectionModePlainText LdapConnectionMode = iota
	LdapConnectionModeSSL                          = iota
	LdapConnectionModeTLS                          = iota
)

var (
	ldapDomain string
)

type LdapAuthenticator struct {
	con *ldap.LDAPConnection
}

type ldapUserStore struct {
	con *ldap.LDAPConnection
	db  *sql.DB
}

func (x *LdapAuthenticator) Authenticate(identity, password string) (er error) {
	if len(password) == 0 {
		// Many LDAP servers (or AD) will allow an anonymous BIND.
		// I've never seen the need for a password-less user authenticated against LDAP.
		er = ErrInvalidPassword
		return
	}
	err := x.con.Bind(fmt.Sprintf(`%v@%v`, identity, ldapDomain), password)
	if err != nil {
		er = NewError(ErrIdentityAuthNotFound, err.Error())
	}

	return
}

func (x *LdapAuthenticator) Close() {
	if x.con != nil {
		x.con.Close()
		x.con = nil
	}
}

func (x *ldapUserStore) SetPassword(userId UserId, password string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	return "", ErrUnsupported
}

func (x *ldapUserStore) ResetPasswordFinish(userId UserId, token string, password string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) CreateIdentity(email, username, firstname, lastname, mobilenumber, password string) (UserId, error) {
	return NullUserId, ErrUnsupported
}

func (x *ldapUserStore) RenameIdentity(oldIdent, newIdent string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) GetIdentities() ([]AuthUser, error) {
	rows, err := x.db.Query(`SELECT userid, email, username, firstname, lastname, mobile FROM authuserstore WHERE (archived = false OR archived IS NULL) ORDER BY username`)
	if err != nil {
		return []AuthUser{}, err
	}
	defer rows.Close()
	result := make([]AuthUser, 0)
	type sqlUser struct {
		userid       sql.NullInt64
		email        sql.NullString
		username     sql.NullString
		firstname    sql.NullString
		lastname     sql.NullString
		mobilenumber sql.NullString
	}
	for rows.Next() {
		user := sqlUser{}
		if err := rows.Scan(&user.userid, &user.email, &user.username, &user.firstname, &user.lastname, &user.mobilenumber); err != nil {
			return []AuthUser{}, err
		}
		result = append(result, AuthUser{UserId(user.userid.Int64), user.email.String, user.username.String, user.firstname.String, user.lastname.String, user.mobilenumber.String})
	}
	if rows.Err() != nil {
		return []AuthUser{}, rows.Err()
	}
	return result, nil
}

func (x *ldapUserStore) ArchiveIdentity(userId UserId) error {
	return ErrUnsupported
}

func (x *ldapUserStore) UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string) error {
	return ErrUnsupported
}

func (x *ldapUserStore) GetIdentityFromUserId(userId UserId) (string, error) {
	row := x.db.QueryRow(`SELECT email FROM authuserstore WHERE userid = $1 AND (archived = false OR archived IS NULL)`, userId)
	var identity string
	if scanErr := row.Scan(&identity); scanErr != nil {
		return "", scanErr
	}
	return identity, nil
}

func (x *ldapUserStore) GetUserIdFromIdentity(identity string) (UserId, error) {
	row := x.db.QueryRow(`SELECT userid FROM authuserstore WHERE email = $1 OR LOWER(username) = $1 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(identity))
	var userId int64
	if scanErr := row.Scan(&userId); scanErr != nil {
		return 0, scanErr
	}
	return UserId(userId), nil
}

func (x *ldapUserStore) GetLdapUsers() ([]AuthUser, error) {
	var attributes []string = []string{
		"sAMAccountName",
		"cn",
		"name",
		"sn",
		"mail",
		"mobile"}

	search_request := ldap.NewSearchRequest(
		"dc=imqs,dc=local",
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		"(objectclass=user)",
		attributes,
		nil)

	sr, err := x.con.Search(search_request)
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

func (x *ldapUserStore) Merge(users []AuthUser) error {
	tx, err := x.db.Begin()
	if err != nil {
		return err
	}
	// Remove users that are not on LDAP but are on our system
	// First we need to map the ldap users
	mappedLdapUsers := make(map[string]*AuthUser)
	for _, user := range users {
		mappedLdapUsers[user.Username] = &user
	}
	userRemovalList := make([]string, 0)
	// Run through the imqs users
	rows, err := tx.Query(`SELECT username from authuserstore WHERE (archived = false OR archived IS NULL)`)
	defer rows.Close()
	if err != nil {
		tx.Rollback()
		return err
	}
	for rows.Next() {
		var username sql.NullString
		if err := rows.Scan(&username); err != nil {
			return err
		}

		// Check if imqs user exists in ldap user map, if not add to the list for removal
		mappedLdapUser := mappedLdapUsers[username.String]
		if mappedLdapUser == nil {
			userRemovalList = append(userRemovalList, username.String)
		}
	}
	//Remove from imqs userstore
	for _, userForRemoval := range userRemovalList {
		_, errRemoveUser := tx.Exec(`UPDATE authuserstore SET archived = $1 WHERE username = $2`, true, userForRemoval)
		if errRemoveUser != nil {
			tx.Rollback()
			return errRemoveUser
		}
	}

	// Insert new ldap users or update existing imqs users
	for _, user := range users {
		insert := false
		row := tx.QueryRow(`SELECT username from authuserstore WHERE username = ($1)`, user.Username)
		scanErr := row.Scan()
		if strings.Index(scanErr.Error(), "no rows in result set") != -1 {
			insert = true
		}

		if insert {
			_, errInsertUser := tx.Exec(`INSERT INTO authuserstore (email, username, firstname, lastname, mobile, archived) VALUES ($1, $2, $3, $4, $5, $6)`, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, false)
			if errInsertUser != nil {
				tx.Rollback()
				return errInsertUser
			}
		} else {
			_, errUpdateUser := tx.Exec(`UPDATE authuserstore SET email = $1, firstname = $3, lastname = $4, mobile = $5 WHERE username = $2`, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber)
			if errUpdateUser != nil {
				tx.Rollback()
				return errUpdateUser
			}
		}
	}
	return tx.Commit()
}

func (x *ldapUserStore) Close() {
	if x.con != nil {
		x.con.Close()
		x.con = nil
	}
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

func NewAuthenticator_LDAP(mode LdapConnectionMode, host string, port uint16) (*LdapAuthenticator, error) {
	ldapAuth := &LdapAuthenticator{}
	// Setup LDAP connection
	con := ldap.NewLDAPConnection(host, port)
	switch mode {
	case LdapConnectionModePlainText:
	case LdapConnectionModeSSL:
		con.IsSSL = true
	case LdapConnectionModeTLS:
		con.IsTLS = true
	}
	if err := con.Connect(); err != nil {
		fmt.Printf("LDAP new. error = '%v'\n", err)
		con.Close()
		return nil, NewError(ErrConnect, err.Error())
	}
	ldapAuth.con = con

	return ldapAuth, nil
}

func NewUserstore_LDAP(conx *DBConnection, mode LdapConnectionMode, host string, port uint16, username, password, domain string) (*ldapUserStore, error) {
	ldapUserStore := &ldapUserStore{}
	var err error
	if ldapUserStore.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	// Setup LDAP connection
	con := ldap.NewLDAPConnection(host, port)
	switch mode {
	case LdapConnectionModePlainText:
	case LdapConnectionModeSSL:
		con.IsSSL = true
	case LdapConnectionModeTLS:
		con.IsTLS = true
	}
	ldapDomain = domain
	if err := con.Connect(); err != nil {
		fmt.Printf("LDAP new. error = '%v'\n", err)
		con.Close()
		return nil, NewError(ErrConnect, err.Error())
	}
	if err := con.Bind(username, password); err != nil {
		return nil, err
	}
	ldapUserStore.con = con

	return ldapUserStore, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LDAP TEST
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type dummyLdapAuthenticatorAndUserStore struct {
	ldapUsers []*LdapUser
	usersLock sync.RWMutex
	db        *sql.DB
}

func NewDummyUserStoreAndAuthenticator_LDAP(conx *DBConnection) (*dummyLdapAuthenticatorAndUserStore, error) {
	dummyLdapAuthUserStore := &dummyLdapAuthenticatorAndUserStore{}
	// Create dummy LDAP users
	ldapUsers := make([]*LdapUser, 0)
	ldapUsers = append(ldapUsers, &LdapUser{Email: "joe@gmail.com", Username: "joe", Firstname: "Firstname", Lastname: "Lastname", Mobilenumber: "Mobilenumber", Password: "123"})
	ldapUsers = append(ldapUsers, &LdapUser{Email: "jack@gmail.com", Username: "jack", Firstname: "Firstname", Lastname: "Lastname", Mobilenumber: "Mobilenumber", Password: "12345"})
	ldapUsers = append(ldapUsers, &LdapUser{Email: "Sam@gmail.com", Username: "Sam", Firstname: "Firstname", Lastname: "Lastname", Mobilenumber: "Mobilenumber", Password: "0000"})
	ldapUsers = append(ldapUsers, &LdapUser{Email: "iHaveNoPermit@gmail.com", Username: "iHaveNoPermit", Firstname: "Firstname", Lastname: "Lastname", Mobilenumber: "Mobilenumber", Password: "123"})
	dummyLdapAuthUserStore.ldapUsers = ldapUsers
	var err error
	if dummyLdapAuthUserStore.db, err = conx.Connect(); err != nil {
		return nil, err
	}

	return dummyLdapAuthUserStore, nil
}

func (x *dummyLdapAuthenticatorAndUserStore) Authenticate(identity, password string) (er error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	user := getLdapUser(x.ldapUsers, identity)
	if user == nil {
		er = ErrIdentityAuthNotFound
	} else if user.Password == password {
		er = nil
	} else {
		er = ErrInvalidPassword
	}

	return
}

func (x *dummyLdapAuthenticatorAndUserStore) SetPassword(userId UserId, password string) error {
	return ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	return "", ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) ResetPasswordFinish(userId UserId, token string, password string) error {
	return ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) CreateIdentity(email, username, firstname, lastname, mobilenumber, password string) (UserId, error) {
	return NullUserId, ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) RenameIdentity(oldIdent, newIdent string) error {
	return ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) GetIdentities() ([]AuthUser, error) {
	rows, err := x.db.Query(`SELECT userid, email, username, firstname, lastname, mobile FROM authuserstore WHERE (archived = false OR archived IS NULL) ORDER BY email`)
	if err != nil {
		return []AuthUser{}, err
	}
	defer rows.Close()
	result := make([]AuthUser, 0)
	type sqlUser struct {
		userid       sql.NullInt64
		email        sql.NullString
		username     sql.NullString
		firstname    sql.NullString
		lastname     sql.NullString
		mobilenumber sql.NullString
	}
	for rows.Next() {
		user := sqlUser{}
		if err := rows.Scan(&user.userid, &user.email, &user.username, &user.firstname, &user.lastname, &user.mobilenumber); err != nil {
			return []AuthUser{}, err
		}
		result = append(result, AuthUser{UserId(user.userid.Int64), user.email.String, user.username.String, user.firstname.String, user.lastname.String, user.mobilenumber.String})
	}
	if rows.Err() != nil {
		return []AuthUser{}, rows.Err()
	}
	return result, nil
}

func (x *dummyLdapAuthenticatorAndUserStore) ArchiveIdentity(userId UserId) error {
	return ErrUnsupported
}

func (x *dummyLdapAuthenticatorAndUserStore) UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserstore SET email = $1, username = $2, firstname = $3, lastname = $4, mobile = $5 WHERE userid = $6 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(email), username, firstname, lastname, mobilenumber, userId); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				tx.Rollback()
				return ErrIdentityAuthNotFound
			}
		} else {
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *dummyLdapAuthenticatorAndUserStore) GetIdentityFromUserId(userId UserId) (string, error) {
	row := x.db.QueryRow(`SELECT email FROM authuserstore WHERE userid = $1 AND (archived = false OR archived IS NULL)`, userId)
	var identity string
	if scanErr := row.Scan(&identity); scanErr != nil {
		return "", scanErr
	}
	return identity, nil
}

func (x *dummyLdapAuthenticatorAndUserStore) GetUserIdFromIdentity(identity string) (UserId, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	row := x.db.QueryRow(`SELECT userid FROM authuserstore WHERE email = $1 OR username = $1 AND (archived = false OR archived IS NULL)`, identity)
	var userId int64
	if scanErr := row.Scan(&userId); scanErr != nil {
		return 0, scanErr
	}
	return UserId(userId), nil
}

func (x *dummyLdapAuthenticatorAndUserStore) GetLdapUsers() ([]AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	//Now we build up and return the list of ldap users ([]AuthUsers)
	ldapUsers := make([]AuthUser, 0)
	for _, ldapUser := range x.ldapUsers {
		ldapUsers = append(ldapUsers, AuthUser{UserId: NullUserId, Email: ldapUser.Email, Username: ldapUser.Username, Firstname: ldapUser.Firstname, Lastname: ldapUser.Lastname, Mobilenumber: ldapUser.Mobilenumber})
	}
	return ldapUsers, nil
}

func (x *dummyLdapAuthenticatorAndUserStore) Merge(users []AuthUser) error {
	tx, err := x.db.Begin()
	if err != nil {
		return err
	}
	for _, user := range users {
		insert := false
		row := tx.QueryRow(`SELECT username from authuserstore WHERE username = ($1)`, user.Username)
		scanErr := row.Scan()
		if strings.Index(scanErr.Error(), "no rows in result set") != -1 {
			insert = true
		}

		if insert {
			_, errInsertUser := tx.Exec(`INSERT INTO authuserstore (email, username, firstname, lastname, mobile, archived) VALUES ($1, $2, $3, $4, $5, $6)`, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, false)
			if errInsertUser != nil {
				tx.Rollback()
				return errInsertUser
			}
		} else {
			_, errUpdateUser := tx.Exec(`UPDATE authuserstore SET email = $1, firstname = $3, lastname = $4, mobile = $5 WHERE username = $2`, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber)
			if errUpdateUser != nil {
				tx.Rollback()
				return errUpdateUser
			}
		}
	}
	return tx.Commit()
}

func (x *dummyLdapAuthenticatorAndUserStore) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}
