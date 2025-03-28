package authaus

import (
	"crypto/tls"
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
		"mobile",
		"userPrincipalName",
	}

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
	if x.config.DebugUserPull {
		fmt.Printf("%23v | %16v | %19v | %45v | %15v\n", "username", "name", "surname", "email", "mobile")
	}
	ldapUsers := make([]AuthUser, len(sr.Entries))
	for i, value := range sr.Entries {
		// We trim the spaces as we have found that a certain ldap user
		// (WilburGS) has an email that ends with a space.
		username := strings.TrimSpace(getAttributeValue(*value, "sAMAccountName"))
		givenName := strings.TrimSpace(getAttributeValue(*value, "givenName"))
		name := strings.TrimSpace(getAttributeValue(*value, "name"))
		surname := strings.TrimSpace(getAttributeValue(*value, "sn"))
		email := strings.TrimSpace(getAttributeValue(*value, "mail"))
		mobile := strings.TrimSpace(getAttributeValue(*value, "mobile"))
		userPrincipalName := strings.TrimSpace(getAttributeValue(*value, "userPrincipalName"))
		if email == "" && strings.Count(userPrincipalName, "@") == 1 {
			// This was first seen in Azure, when integrating with DTPW (Department of Transport and Public Works)
			email = userPrincipalName
		}
		firstName := givenName
		if firstName == "" && surname == "" && name != "" {
			// We're in dubious best-guess-for-common-english territory here
			firstSpace := strings.Index(name, " ")
			if firstSpace != -1 {
				firstName = name[:firstSpace]
				surname = name[firstSpace+1:]
			}
		}
		if x.config.DebugUserPull {
			fmt.Printf("%23v | %16v | %19v | %45v | %15v\n", username, firstName, surname, email, mobile)
		}
		ldapUsers[i] = AuthUser{UserId: NullUserId, Email: email, Username: username, Firstname: firstName, Lastname: surname, Mobilenumber: mobile}
	}
	return ldapUsers, nil
}

func MergeLDAP(c *Central) {
	ldapUsers, err := c.ldap.GetLdapUsers()
	if err != nil {
		c.Log.Warnf("Failed to retrieve users from LDAP server for merge to take place (%v)", err)
		return
	}
	imqsUsers, err := c.userStore.GetIdentities(GetIdentitiesFlagNone)
	if err != nil {
		c.Log.Warnf("Failed to retrieve users from Userstore for merge to take place (%v)", err)
		return
	}
	MergeLdapUsersIntoLocalUserStore(c, ldapUsers, imqsUsers)
}

// We are reading users from LDAP/AD and merging them into the IMQS userstore
func MergeLdapUsersIntoLocalUserStore(x *Central, ldapUsers []AuthUser, imqsUsers []AuthUser) {
	// Create maps from arrays
	imqsUserUsernameMap := make(map[string]AuthUser)
	for _, imqsUser := range imqsUsers {
		if len(imqsUser.Username) > 0 {
			imqsUserUsernameMap[CanonicalizeIdentity(imqsUser.Username)] = imqsUser
		}
	}

	imqsUserEmailMap := make(map[string]AuthUser)
	for _, imqsUser := range imqsUsers {
		if len(imqsUser.Email) > 0 {
			imqsUserEmailMap[CanonicalizeIdentity(imqsUser.Email)] = imqsUser
		}
	}

	ldapUserMap := make(map[string]AuthUser)
	for _, ldapUser := range ldapUsers {
		ldapUserMap[CanonicalizeIdentity(ldapUser.Username)] = ldapUser
	}

	// Insert or update
	for _, ldapUser := range ldapUsers {
		// This log is useful when debugging, but in regular operation the relevant details go into the logs when something changes (see below)
		// x.Log.Infof("Merging user %20s %20s %20s '%s'", ldapUser.Username, ldapUser.Firstname, ldapUser.Lastname, ldapUser.Email)
		imqsUser, foundWithUsername := imqsUserUsernameMap[CanonicalizeIdentity(ldapUser.Username)]
		foundWithEmail := false
		if !foundWithUsername {
			imqsUser, foundWithEmail = imqsUserEmailMap[CanonicalizeIdentity(ldapUser.Email)]
		}

		user := imqsUser
		user.Email = ldapUser.Email
		user.Username = ldapUser.Username
		user.Firstname = ldapUser.Firstname
		user.Lastname = ldapUser.Lastname
		user.Mobilenumber = ldapUser.Mobilenumber
		user.Type = UserTypeLDAP
		if !foundWithUsername && !foundWithEmail {
			x.Log.Infof("Creating new user %v:%v", user.Username, user.Email)
			user.Created = time.Now().UTC()
			user.CreatedBy = UserIdLDAPMerge
			user.Modified = time.Now().UTC()
			user.ModifiedBy = UserIdLDAPMerge

			// WARNING: Weird thing that looked like a compiler bug:
			// We have found that a certain ldap user (WilburGS) has an email that ends with a space.
			// This space mysteriously disappears when the address of `user` is taken.
			if _, err := x.userStore.CreateIdentity(&user, ""); err != nil {
				x.Log.Warnf("LDAP merge: Create identity failed with (%v)", err)
			}

			// Log to audit trail user created
			if x.Auditor != nil {
				contextData := userInfoToAuditTrailJSON(user, "")
				x.Auditor.AuditUserAction(x.GetUserNameFromUserId(user.CreatedBy),
					"User Profile: "+user.Username, contextData, AuditActionCreated)
			}
		} else if foundWithEmail || !equalsForLDAPMerge(user, imqsUser) {
			if imqsUser.Type == UserTypeDefault {
				x.Log.Infof("Updating user of Default user type, to LDAP user type: %v", imqsUser.Email)
			}
			user.Modified = time.Now().UTC()
			user.ModifiedBy = UserIdLDAPMerge

			// WARNING: Weird thing that looked like a compiler bug:
			// We have found that a certain ldap user (WilburGS) has an email that ends with a space.
			// This space mysteriously disappears when the address of `user` is taken.
			if err := x.userStore.UpdateIdentity(&user); err != nil {
				x.Log.Warnf("LDAP merge: Update identity (%v) failed with (%v)", user.UserId, err)
				x.Log.Warnf("          : %v", UserInfoToJSON(user))
			} else {
				x.Log.Infof("LDAP merge: Updated user %v", user.Username)
				x.Log.Infof("old: %v", UserInfoToJSON(imqsUser))
				x.Log.Infof("new: %v", UserInfoToJSON(user))
			}

			// Log to audit trail user updated
			if x.Auditor != nil {
				contextData := userInfoToAuditTrailJSON(user, "")
				userChanges, e := UserInfoDiff(imqsUser, user)
				if e != nil {
					x.Log.Warnf("LDAP merge: Could not diff user %v (%v)", user.UserId, e)
				}
				logMessage := UserDiffLogMessage(userChanges, user)
				x.Auditor.AuditUserAction(x.GetUserNameFromUserId(user.ModifiedBy),
					logMessage, contextData, AuditActionUpdated)
			}
		}
	}

	// Remove
	for _, imqsUser := range imqsUsers {
		_, found := ldapUserMap[CanonicalizeIdentity(imqsUser.Username)]
		if !found {
			// We only archive ldap users that are not on the ldap system, but are not on ours, imqs users should remain
			if imqsUser.Type == UserTypeLDAP {
				if err := x.userStore.ArchiveIdentity(imqsUser.UserId); err != nil {
					x.Log.Warnf("LDAP merge: Archive identity failed with (%v)", err)
				}

				// Log to audit trail user deleted
				if x.Auditor != nil {
					contextData := userInfoToAuditTrailJSON(imqsUser, "")
					x.Auditor.AuditUserAction(x.GetUserNameFromUserId(UserIdLDAPMerge), "User Profile: "+imqsUser.Username, contextData, AuditActionDeleted)
				}
			}
		}
	}
}

func equalsForLDAPMerge(a, b AuthUser) bool {
	return a.Email == b.Email &&
		a.Firstname == b.Firstname &&
		a.Lastname == b.Lastname &&
		a.Mobilenumber == b.Mobilenumber &&
		a.Username == b.Username
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
	if config.InsecureSkipVerify {
		con.TlsConfig = &tls.Config{}
		con.TlsConfig.InsecureSkipVerify = config.InsecureSkipVerify
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
