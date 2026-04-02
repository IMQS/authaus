package authaus

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/IMQS/log"
	"github.com/go-ldap/ldap/v3"
	"net"
	"strconv"
	"strings"
	"time"
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

func (x *LdapImpl) GetConfig() *ConfigLDAP {
	return x.config
}

type ldapEntry struct {
	UserName          string
	GivenName         string
	Name              string
	Surname           string
	Email             string
	Mobile            string
	UserPrincipalName string
	ExpiryValue       string
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
	defer func() {
		_ = con.Close()
	}()
	// We need to know whether we must add the domain to the identity by checking
	// if it contains '@'
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

func (x *LdapImpl) GetLdapUsers(log *log.Logger) ([]AuthUser, error) {
	var attributes = []string{
		"sAMAccountName",
		"givenName",
		"name",
		"sn",
		"mail",
		"mobile",
		"userPrincipalName",
		"msDS-UserPasswordExpiryTimeComputed",
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
	defer func() {
		_ = con.Close()
	}()
	sr, err := con.SearchWithPaging(searchRequest, 100)
	if err != nil {
		fmt.Println("LDAP search failed: ", err)
		return nil, err
	}

	if x.config.DebugUserPull {
		// print hierarchy by iterating over the tree, depth first
		log.Infof("LDAP hierarchy:\n")
		printHierarchy(extractHierarchy(sr), "", true, log)
	}

	getAttributeValue := func(entry ldap.Entry, attribute string) string {
		values := entry.GetAttributeValues(attribute)
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}

	ldapSource := make([]ldapEntry, len(sr.Entries))
	ldapUsers := make([]AuthUser, len(sr.Entries))
	if x.config.DebugUserPull {
		log.Infof("%d records retrieved from LDAP server...\n", len(sr.Entries))
	}
	allAttributes := make(map[string]struct{})
	for i, value := range sr.Entries {
		// We trim the spaces as we have found that a certain ldap user
		// (WilburGS) has an email that ends with a space.
		if x.config.DebugUserPull {
			log.Infof("LDAP raw entry: %+v\n", *value)
		}

		for _, attr := range value.Attributes {
			allAttributes[attr.Name] = struct{}{}
		}

		newEntry := ldapEntry{}
		fmt.Printf(getAttributeValue(*value, "msDS-UserPasswordExpiryTimeComputed"))
		newEntry.UserName = strings.TrimSpace(getAttributeValue(*value, "sAMAccountName"))
		newEntry.GivenName = strings.TrimSpace(getAttributeValue(*value, "givenName"))
		newEntry.Name = strings.TrimSpace(getAttributeValue(*value, "name"))
		newEntry.Surname = strings.TrimSpace(getAttributeValue(*value, "sn"))
		newEntry.Email = strings.TrimSpace(getAttributeValue(*value, "mail"))
		newEntry.Mobile = strings.TrimSpace(getAttributeValue(*value, "mobile"))
		newEntry.UserPrincipalName = strings.TrimSpace(getAttributeValue(*value, "userPrincipalName"))
		newEntry.ExpiryValue = strings.TrimSpace(getAttributeValue(*value, "msDS-UserPasswordExpiryTimeComputed"))
		if newEntry.Email == "" && strings.Count(newEntry.UserPrincipalName, "@") == 1 {
			// This was first seen in Azure, when integrating with DTPW (Department of Transport and Public Works)
			newEntry.Email = newEntry.UserPrincipalName
		}
		firstName := newEntry.GivenName
		if firstName == "" && newEntry.Surname == "" && newEntry.Name != "" {
			// We're in dubious best-guess-for-common-english territory here
			firstSpace := strings.Index(newEntry.Name, " ")
			if firstSpace != -1 {
				firstName = newEntry.Name[:firstSpace]
				newEntry.Surname = newEntry.Name[firstSpace+1:]
			}
		}
		ldapSource[i] = newEntry
		ldapUsers[i] = AuthUser{UserId: NullUserId, Email: newEntry.Email, Username: newEntry.UserName, Firstname: firstName, Lastname: newEntry.Surname, Mobilenumber: newEntry.Mobile}
	}

	// print
	if x.config.DebugUserPull {
		log.Infof("All LDAP attributes seen:\n")
		attributeNames := make([]string, 0, len(allAttributes))
		for attrName := range allAttributes {
			attributeNames = append(attributeNames, attrName)
		}
		log.Infof("all attributes: %v\n", strings.Join(attributeNames, ", "))

		log.Infof("---\n")
		log.Infof("LDAP source data:\n")
		log.Infof("%23v | %20v | %26v | %25v | %45v | %15v | %45v | %20v | %20v\n", "sAMAccountName", "givenName", "name", "sn", "mail", "mobile", "userPrincipalName", "msDS-UserPasswordExpiryTimeComputed", "Expired (calc)")
		log.Infof("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
		for _, entry := range ldapSource {
			log.Infof("%23v | %20v | %26v | %25v | %45v | %15v | %45v | %20v |%20v\n",
				entry.UserName, entry.GivenName, entry.Name, entry.Surname, entry.Email, entry.Mobile, entry.UserPrincipalName, entry.ExpiryValue, calcExpiryDate(entry.ExpiryValue))
		}

		log.Infof("\n")
		log.Infof("Mapped to Auth users:\n")
		log.Infof("%23v | %16v | %19v | %45v | %15v\n", "username", "firstname", "lastname", "email", "mobile")
		log.Infof("----------------------------------------------------------------------------------------------------------------------------------\n")
		for _, user := range ldapUsers {
			log.Infof("%23v | %16v | %19v | %45v | %15v\n", user.Username, user.Firstname, user.Lastname, user.Email, user.Mobilenumber)
		}
	}
	return ldapUsers, nil
}

func calcExpiryDate(value string) string {
	// msDS-UserPasswordExpiryTimeComputed is a Windows FileTime, which is the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	// To convert it to a Go time.Time, we can use the following calculation:
	const windowsFileTimeOffset = 116444736000000000 // Number of 100-nanosecond intervals between 1601 and 1970
	fileTimeInt, err := strconv.ParseInt(value, 10, 64)
	if fileTimeInt == 9223372036854775807 {
		// This value indicates that the password never expires
		return "never" // Return zero time to indicate no expiry
	}
	if fileTimeInt == 0 {
		return "exired"
	}
	if err != nil {
		return "error"
	}

	unixTime := (fileTimeInt - windowsFileTimeOffset) / 10000000 // Convert to seconds

	return fmt.Sprintf("%v", time.Unix(unixTime, 0).UTC())
}

type hierarchyNode struct {
	name     string
	nodeType string
	children map[string]*hierarchyNode
}

type pathElement struct {
	name     string
	nodeType string
}

// formatHierarchyPath returns the formatted path string for a node.
// If nodeType is "CN" and printNodesIfCN is true, uses colon separator.
func formatHierarchyPath(pathPrefix, nodeName, nodeType string, printNodesIfCN bool) string {
	if nodeType == "CN" && printNodesIfCN {
		return printTrunc(pathPrefix+" : "+nodeName, 120, "...")
	}
	return printTrunc(pathPrefix+"/"+nodeName, 120, "...")
}

func printHierarchy(hierarchy *hierarchyNode, pathPrefix string, printNodesIfCN bool, log *log.Logger) {
	if hierarchy == nil {
		return
	}
	currentNode := hierarchy
	// print current node
	log.Infof("Node: %s\n", formatHierarchyPath(pathPrefix, currentNode.name, currentNode.nodeType, printNodesIfCN))

	// iterate through children
	pathPrefix = pathPrefix + "/" + currentNode.name
	for _, child := range currentNode.children {
		printHierarchy(child, pathPrefix, printNodesIfCN, log)
	}
}

// printTrunc produces an output such that len(output) <= maxLength
//
// If len(str) > maxLength, it will truncate str and append abbrevString such
// that the output is still of length maxLength.
func printTrunc(str string, maxLength int, abbrevString string) string {
	if len(str) > maxLength {
		return str[:maxLength-len(abbrevString)] + abbrevString
	} else {
		return str
	}
}

func extractHierarchy(sr *ldap.SearchResult) *hierarchyNode {
	tree := &hierarchyNode{
		name:     "ROOT",
		nodeType: "ROOT",
		children: make(map[string]*hierarchyNode),
	}

	currentNode := tree
	for _, a := range sr.Entries {
		currentNode = tree
		// New code
		pathElements := extractPath(a.DN)
		for _, part := range pathElements {
			childNode, found := currentNode.children[part.name]
			if !found {
				childNode = &hierarchyNode{
					name:     part.name,
					nodeType: part.nodeType,
					children: make(map[string]*hierarchyNode),
				}
				currentNode.children[part.name] = childNode
			}
			currentNode = childNode
		}
	}
	return tree
}

// extractPath extracts the top-down path elements from a DN string
func extractPath(dn string) []pathElement {
	parts := strings.Split(dn, ",")
	result := make([]pathElement, 0, len(parts))
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		equalIndex := strings.Index(part, "=")
		if equalIndex != -1 && equalIndex < len(part)-1 {
			result = append(result, pathElement{part[equalIndex+1:], part[:equalIndex]})
		}
	}
	return result
}

func MergeLDAP(c *Central) {
	ldapUsers, err := c.ldap.GetLdapUsers(c.Log)
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

// MergeLdapUsersIntoLocalUserStore
//
// Reads users from LDAP/AD and merges them into the IMQS user store
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

func NewLDAPConnectAndBind(config *ConfigLDAP) (*ldap.Conn, error) {
	con, err := NewLDAPConnect(config)
	if err != nil {
		return nil, err
	}
	if err = con.Bind(config.LdapUsername, config.LdapPassword); err != nil {
		return nil, err
	}
	return con, nil
}

// NewLDAPConnect creates a new LDAP connection based on the configuration
// provided
//
// If the ldapPort is not specified, it defaults to 389.
// If connection is not-null, the calling function is required to close the
// connection when done with it.
func NewLDAPConnect(config *ConfigLDAP) (*ldap.Conn, error) {
	if config.LdapPort == 0 {
		config.LdapPort = 389
	}

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	ldapMode, legalLdapMode := configLdapNameToMode[config.Encryption]
	if !legalLdapMode {
		return nil, errors.New(fmt.Sprintf("Unknown ldap mode %v. Recognized modes are TLS, SSL, and empty for unencrypted", config.Encryption))
	}

	// TODO : Switch protocol explicitly for SSL mode to ldaps://
	addr := "ldap://" + config.LdapHost + fmt.Sprintf(":%d", config.LdapPort)

	switch ldapMode {
	case LdapConnectionModePlainText:
		c, e := ldap.DialURL(addr, ldap.DialWithDialer(dialer))
		if e != nil {
			return nil, e
		}
		c.SetTimeout(10 * time.Second)
		return c, e
	// DEPRECATED
	case LdapConnectionModeSSL:
		// Use ldaps:// protocol and default port 636 if not specified
		sslPort := config.LdapPort
		if sslPort == 0 || sslPort == 389 {
			sslPort = 636
		}
		ldapsAddr := "ldaps://" + config.LdapHost + fmt.Sprintf(":%d", sslPort)
		tlsConfig := &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}
		c, e := ldap.DialURL(ldapsAddr, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
		if e != nil {
			return nil, e
		}
		c.SetTimeout(10 * time.Second)
		return c, e
	case LdapConnectionModeTLS:
		tlsConfig := &tls.Config{}
		if config.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = config.InsecureSkipVerify
		}
		c, e := ldap.DialURL(addr, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
		if e != nil {
			return nil, e
		}
		c.SetTimeout(10 * time.Second)
		return c, e
	default:
		return nil, errors.New("unimplemented LDAP connection mode")
	}
}

func NewAuthenticator_LDAP(config *ConfigLDAP) *LdapImpl {
	return &LdapImpl{
		config: config,
	}
}
