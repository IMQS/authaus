package authaus

// This file contains functionality for reading the users from a Microsoft Azure Active Directory,
// via the Microsoft Graph API.
// See https://docs.microsoft.com/en-us/graph/use-the-api
// Once this is configured, the Authaus user database is periodically synchronized from
// the Azure Active Directory. This has the advantage that an administrator can set up
// a user's permissions before that user logs in for the first time.
//
// Sync Considerations
//
// It's relatively fast to ask Microsoft for the list of users in an AAD (a few seconds for
// a few hundred). However, fetching the roles that each user belongs to is much slower,
// because each fetch is a different HTTP request, and no matter what our bandwidth is,
// we pay a latency cost if we're going over the sea.
//
// To mitigate this cost, we parallelize the fetching of the roles, and this has an almost
// linear speedup over fetching them serially.

import (
	"errors"
	"fmt"
	"github.com/IMQS/log"
	"strings"
	"sync"
	"time"
)

// ConfigMSAAD is the JSON definition for the Microsoft Azure Active Directory synchronization settings
type ConfigMSAAD struct {
	Verbose                              bool                                // If true, then emit verbose logging
	DryRun                               bool                                // If true, don't actually take any action, just log the intended actions
	TenantID                             string                              // Your tenant UUID (ie ID of your AAD instance)
	ClientID                             string                              // Your client UUID (ie ID of your application)
	ClientSecret                         string                              // Secrets used for authenticating Azure AD requests
	ClientSecretExpiryDate               *time.Time                          // Optional expiry date for the client secret (RFC3339 format)
	MergeIntervalSeconds                 int                                 // If non-zero, then overrides the merge interval
	DefaultRoles                         []string                            // Roles that are activated by default if a user has any one of the AAD roles
	RoleToGroup                          map[string]string                   // Map from principleName of AAD role, to Authaus group.
	AllowArchiveUser                     bool                                // If true, then archive users who no longer have the relevant roles in the AAD
	PassthroughClientIDs                 []string                            // Client IDs of trusted IMQS apps utilising app-to-app passthrough auth
	SecretExpiryNotificationDays         int                                 // Number of days before expiry to trigger notification (default: 14)
	SecretExpiryCheckIntervalHours       int                                 // Hours between secret expiry checks (default: 1)
	SecretExpiryNotificationCallback     ClientSecretExpiryNotificationFunc  // Callback function for secret expiry notifications
}

// MSAADInterface
//
// Interface to abstract the fetching of roles and users, allowing mocking
// of dependencies (DBs, API functions).
// Initialize must be called on all implementing structs.
type MSAADInterface interface {
	Config() ConfigMSAAD
	Parent() *Central
	Provider() MSAADProviderI
	Initialize(parent *Central, log *log.Logger) error
	SynchronizeUsers() error
	IsShuttingDown() bool
	SetConfig(msaad ConfigMSAAD)
	SetProvider(provider MSAADProviderI)
}

// MSAADProviderI
//
// Interface to abstract the fetching of roles and users, allowing mocking
// of returns.
// Initialize must be called on all implementing structs.
type MSAADProviderI interface {
	GetAADUsers() ([]*msaadUser, error)
	GetUserAssignments(user *msaadUser, threadGroupID int) (errGlobal error, quit bool)
	Initialize(parent MSAADInterface, log *log.Logger) error
	Parent() MSAADInterface
	IsShuttingDown() bool
}

// MatchType attempts to give more information about the type of match that was
// detected
type MatchType int

const (
	MatchTypeNone       MatchType = 0
	MatchTypeStartsWith           = 1 << (iota - 1)
	MatchTypeEndsWith
	MatchTypeExact
	MatchTypeStandard = MatchTypeExact | MatchTypeStartsWith | MatchTypeEndsWith
)

func (u *msaadUser) hasRoleByPrincipalDisplayName(principalDisplayName string, preferredMatchConditions MatchType) bool {
	for _, r := range u.roles {
		if preferredMatchConditions == MatchTypeNone {
			preferredMatchConditions = MatchTypeStandard
		}

		if Match(principalDisplayName, r.PrincipalDisplayName)&preferredMatchConditions != 0 {
			return true
		}
	}
	return false
}

// Match attempts to provide a best-effort match between two strings.
// Exact match is the most preferred, followed by starts-with, and then ends-with.
// If neither string contains a wildcard, only MatchTypeExact and MatchTypeNone
// are considered.
//
// A wildcard is indicated by a TRAILING '*' for either string.
// If both strings contain a wildcard, then the shortest string is considered for
// the match type.
//
// Limitations:
//
// (a) If both strings contain a wildcard, then the result may be ambiguous.
//
// (b) The wildcard can only be at the end of the string, marking the preceding
// characters as the potential match.
//
// (c) If the wildcard is not at either end of the string, then the string is
// treated as a normal string.
func Match(lhs, rhs string) MatchType {
	lhs, rhs = swapIfNecessary(lhs, rhs)

	var (
		isWildcard    = strings.Contains(lhs, "*")
		lhsNoWildcard = strings.TrimRight(lhs, "*")
	)

	// Because of swap, we can assume that the lhs string in this scope any of
	// the candidate strings were to contain a wildcard, it would at least be the
	// lhs string
	if !isWildcard && lhs == rhs {
		return MatchTypeExact
	} else if isWildcard && strings.HasPrefix(rhs, lhsNoWildcard) {
		return MatchTypeStartsWith
	} else if isWildcard && strings.HasSuffix(rhs, lhsNoWildcard) {
		return MatchTypeEndsWith
	}

	return MatchTypeNone
}

// swapIfNecessary is a rudimentary helper that allows us to swap the contents
// of two strings if any one of the following conditions is met:
// (a) rhs is shorter than lhs
// (b) rhs contains a wildcard (either at the beginning or the end) and lhs does
// not
// Situations where both strings have wildcards is not supported and may produce
// unreliable results.
func swapIfNecessary(lhs, rhs string) (string, string) {
	lhsContainsWildcard := strings.Contains(lhs, "*")
	rhsContainsWildcard := strings.Contains(rhs, "*")

	if len(rhs) < len(lhs) {
		return rhs, lhs
	} else if lhsContainsWildcard && !rhsContainsWildcard {
		return lhs, rhs
	} else if rhsContainsWildcard && !lhsContainsWildcard {
		return rhs, lhs
	}

	return lhs, rhs
}

// cachedRoleGroups is a cache of all the internal groups, as well as tables that allow us to
// access them quickly by ID and by Name
type cachedRoleGroups struct {
	groups      []*AuthGroup
	nameToGroup map[string]*AuthGroup
	idToGroup   map[GroupIDU32]*AuthGroup
}

func (crg *cachedRoleGroups) idToGroupName(i GroupIDU32) string {
	groupName := "<unknown>"
	if g, ok := crg.idToGroup[i]; ok {
		groupName = g.Name
	}
	return groupName
}

// MSAAD is a container for the Microsoft Azure Active Directory synchronization system
type MSAAD struct {
	config   ConfigMSAAD
	provider MSAADProviderI
	parent   *Central
	log      *log.Logger

	numAADRoleFetches int
}

func (m *MSAAD) Provider() MSAADProviderI {
	return m.provider
}

func (m *MSAAD) SetProvider(provider MSAADProviderI) {
	m.provider = provider
}

func (m *MSAAD) Config() ConfigMSAAD {
	return m.config
}

func (m *MSAAD) Parent() *Central {
	return m.parent
}

func (m *MSAAD) SetConfig(msaad ConfigMSAAD) {
	m.config = msaad
}

// Initialize seeks to initialize the parent context on the MSAAD object
func (m *MSAAD) Initialize(parent *Central, log *log.Logger) error {
	if parent == nil {
		return fmt.Errorf("MSAAD parent parameter is nil")
	}
	m.parent = parent
	if log == nil {
		return fmt.Errorf("MSAAD logger is nil")
	}

	m.log = log
	if m.Provider() != nil {
		err := m.Provider().Initialize(m, m.log)
		if err != nil {
			return fmt.Errorf("could not initialise MSAAD provider, %w", err)
		}
	} else {
		return fmt.Errorf("MSAAD provider is null")
	}

	// Run a loop that checks for MSAAD client secret expiry and triggers notifications
	go func() {
		interval := m.config.SecretExpiryCheckIntervalHours
		if interval == 0 {
			interval = 1 // Default to 1 hour
		}
		// Startup grace
		time.Sleep(15 * time.Second)
		for !m.IsShuttingDown() {
			m.checkSecretExpiry()
			time.Sleep(time.Duration(interval) * time.Hour)
		}
	}()

	return nil
}

// SynchronizeUsers rebuilds the role groups cache, as well as re-fetches the
// users from MSAAD, for the purpose of bringing IMQS' internal roledb cache and
// postgres database up to date
func (m *MSAAD) SynchronizeUsers() error {
	cachedRoleGroups, err := m.buildCachedRoleGroups()
	if err != nil {
		return err
	}

	// Log errors about missing internal group names (this is a config mistake)
	// We do this check once during sync, to avoid emitting this error during the sync of every user.
	for aadRole, internalGroupName := range m.Config().RoleToGroup {
		if _, ok := cachedRoleGroups.nameToGroup[internalGroupName]; !ok {
			m.log.Errorf("MSAAD internal group %v not recognized (for sync from %v)", internalGroupName, aadRole)
		}
	}

	// Fetch users
	aadUsers, err := m.provider.GetAADUsers()
	if err != nil {
		return err
	}

	// Augment AAD user data with AAD roles
	if len(m.Config().RoleToGroup) != 0 || len(m.Config().DefaultRoles) != 0 {
		err = m.populateAADRoles(aadUsers)
		if err != nil {
			// Quit without merging, because we run the risk of archiving users that we did not successfully receive.
			// See "if !insideAAD" in the code below.
			return err
		}
	}

	// Merge users into Authaus database
	existingUsers, err := m.parent.userStore.GetIdentities(GetIdentitiesFlagNone)
	if err != nil {
		return err
	}
	emailToExisting := map[string]int{}
	uuidToExisting := map[string]int{}
	for i, u := range existingUsers {
		emailToExisting[CanonicalizeIdentity(u.Email)] = i
		if u.ExternalUUID != "" {
			uuidToExisting[u.ExternalUUID] = i
		}
	}

	for _, aadUser := range aadUsers {
		aadEmailClean := aadUser.profile.bestEmail()
		if aadEmailClean == "" {
			continue
		}
		aadEmailClean = CanonicalizeIdentity(aadEmailClean)

		// MATCHING
		// First attempt: UUID
		ix, foundExisting := uuidToExisting[aadUser.profile.ID]
		if !foundExisting {
			// Second attempt: email

			// I'm not sure if this even should be here...the external UUID should
			// be enough. We have a few scenarios:
			// 1 - the user was local/LDAP and needs to be moved to MSAAD
			//		are we really going to just trust that it is the same user?
			// 2 - the user's got a NEW account in MSAAD and was re-invited,
			//		in which case we also should not assume anything about the user...
			//		especially since MSAAD would not be assuming anything about the user.
			// 3 - there is a third possibility, moving the guest tenant (us),
			//		in which case the email and home-tenant UPN would be the same.
			//		Is that enough to assume that the user is the same?
			// So, I would vote for removing this line. ALL users should start
			// from scratch when we move over to MSAAD.???
			ix, foundExisting = emailToExisting[aadEmailClean]
		}
		internalUserID := UserId(0)
		if foundExisting {
			// check if user needs to be updated
			internalUserID = existingUsers[ix].UserId
			// In the case where the user was NOT found using UUID, the user has been created manually or
			// by some other means. Regardless, since the user exists in MSAAD (by email/UserPrincipalName, it needs to be updated with the
			// correct references and its type set to MSAAD
			if aadUser.profile.injectIntoAuthUser(&existingUsers[ix]) {
				if m.Config().DryRun {
					m.log.Infof("MSAAD dry-run: Update user %v %v %v", aadUser.profile.DisplayName, aadEmailClean, aadUser.profile.ID)
				} else {
					m.log.Infof("MSAAD update user %v %v %v", aadUser.profile.DisplayName, aadEmailClean, aadUser.profile.ID)
					existingUsers[ix].Modified = time.Now()
					existingUsers[ix].ModifiedBy = UserIdMSAADMerge
					if err := m.parent.userStore.UpdateIdentity(&existingUsers[ix]); err != nil {
						m.log.Warnf("MSAAD: Update user %v failed: %v", aadUser.profile.ID, err)
					} else {
						if m.parent.Auditor != nil {
							contextData := userInfoToAuditTrailJSON(existingUsers[ix], "")
							m.parent.Auditor.AuditUserAction(
								m.parent.GetUserNameFromUserId(existingUsers[ix].ModifiedBy),
								"User Profile: "+existingUsers[ix].Username+" (user details)", contextData, AuditActionUpdated)
						}
					}
				}
			}
		} else if m.userBelongsHere(aadUser, MatchTypeStandard) {
			// user does not exist, so create it
			if m.Config().DryRun {
				m.log.Infof("MSAAD dry-run: Create new user %v %v", aadUser.profile.DisplayName, aadEmailClean)
			} else {
				internalUserID = m.CreateOrUnarchiveUser(aadUser)
			}
		}

		if internalUserID != UserId(0) {
			// update groups of user
			if changed, err := m.syncRoles(cachedRoleGroups, aadUser, internalUserID); err != nil {
				m.log.Errorf("MSAAD failed to synchronize roles for user %v: %v", aadUser.profile.DisplayName, err)
			} else {
				if changed && m.parent.Auditor != nil {
					contextData := msaadUserInfoToAuditTrailJSON(*aadUser, internalUserID, "")
					m.parent.Auditor.AuditUserAction(m.parent.GetUserNameFromUserId(UserIdMSAADMerge),
						"User Profile: "+aadUser.profile.bestEmail()+" (groups updated)", contextData, AuditActionUpdated)
				}
			}
		}
	}

	// Remove Authaus users that no longer exist in the AAD
	if m.config.AllowArchiveUser {
		idToAAD := map[string]int{}
		for i, aadUser := range aadUsers {
			if m.userBelongsHere(aadUser, MatchTypeStandard) {
				idToAAD[aadUser.profile.ID] = i
			}
		}

		for _, user := range existingUsers {
			if user.Type != UserTypeMSAAD {
				continue
			}

			_, insideAAD := idToAAD[user.ExternalUUID]
			if !insideAAD {
				if m.config.DryRun {
					m.log.Infof("MSAAD dry-run: delete user %v %v", user.ExternalUUID, user.Email)
				} else {
					m.log.Infof("MSAAD Archive user %v %v", user.ExternalUUID, user.Email)
					if err := m.parent.userStore.ArchiveIdentity(user.UserId); err != nil {
						m.log.Errorf("MSAAD Archive of %v failed: %v", user.ExternalUUID, err)
					} else {
						if m.parent.Auditor != nil {
							contextData := userInfoToAuditTrailJSON(user, "")
							m.parent.Auditor.AuditUserAction(m.parent.GetUserNameFromUserId(UserIdMSAADMerge),
								"User Profile: "+user.Username, contextData, AuditActionDeleted)
						}
						// clear the permit
						permit := &Permit{}
						err := m.parent.SetPermit(user.UserId, permit)
						if err != nil {
							m.log.Errorf("MSAAD failed to clear permit for user %v: %v", user.Username, err)
						}
						// clear the session
						err = m.parent.InvalidateSessionsForIdentity(user.UserId)
						if err != nil {
							m.log.Errorf("MSAAD failed to invalidate sessions for user %v: %v", user.Username, err)
						}
					}
				}
			}
		}
	}

	return nil
}

func (m *MSAAD) CreateOrUnarchiveUser(aadUser *msaadUser) UserId {
	// first check if the same user was not archived
	user := aadUser.profile.toAuthUser()
	m.log.Infof("MSAAD create / unarchive user %v, mail: %v",
		aadUser.profile.DisplayName,
		aadUser.profile.Mail,
	)
	user.Created = time.Now()
	user.Modified = user.Created
	user.CreatedBy = UserIdMSAADMerge
	user.ModifiedBy = UserIdMSAADMerge

	found := false
	archivedUserId := UserId(0)
	var errArchive error
	if m.config.AllowArchiveUser {
		found, archivedUserId, errArchive = m.parent.userStore.MatchArchivedUserExtUUID(user.ExternalUUID)
		if errArchive != nil {
			m.log.Errorf("MSAAD: Match archived user %v failed with error: %v", user.Email, errArchive)
			return UserId(0)
		}
		user.UserId = archivedUserId
	}
	if m.config.AllowArchiveUser && found {
		// unarchive user
		if err2 := m.parent.userStore.UnarchiveIdentity(archivedUserId); err2 != nil {
			m.log.Errorf("MSAAD: Unarchive identity %v failed: %v", user.Email, err2)
			return UserId(0)
		} else {
			m.log.Infof("MSAAD: Successfully unarchived identity: %v", user.Email)
			if m.parent.Auditor != nil {
				contextData := userInfoToAuditTrailJSON(user, "")
				m.parent.Auditor.AuditUserAction(m.parent.GetUserNameFromUserId(user.CreatedBy),
					"User Profile: "+user.Username, contextData, AuditActionCreated)
			}
			return archivedUserId
		}
	}
	// create user
	if newUserID, err := m.parent.userStore.CreateIdentity(&user, ""); err != nil {
		m.log.Warnf("MSAAD: Create identity %v failed: %v", user.Email, err)
		return UserId(0)
	} else {
		if m.parent.Auditor != nil {
			contextData := userInfoToAuditTrailJSON(user, "")
			m.parent.Auditor.AuditUserAction(m.parent.GetUserNameFromUserId(user.CreatedBy),
				"User Profile: "+user.Username, contextData, AuditActionCreated)
		}
		return newUserID
	}
}

func (m *MSAAD) IsShuttingDown() bool {
	return m.parent.IsShuttingDown()
}

// userBelongsHere tells us whether or not the user has at least one of the
// permissions that is associated with IMQS.
func (m *MSAAD) userBelongsHere(user *msaadUser, matchType MatchType) bool {
	for azureName := range m.config.RoleToGroup {
		if user.hasRoleByPrincipalDisplayName(azureName, matchType) {
			return true
		}
	}

	return false
}

func (m *MSAAD) buildCachedRoleGroups() (*cachedRoleGroups, error) {
	cache := &cachedRoleGroups{
		idToGroup:   map[GroupIDU32]*AuthGroup{},
		nameToGroup: map[string]*AuthGroup{},
	}
	groups, err := m.parent.GetRoleGroupDB().GetGroups()
	if err != nil {
		return nil, err
	}
	cache.groups = groups
	for _, g := range groups {
		cache.idToGroup[g.ID] = g
		cache.nameToGroup[g.Name] = g
	}
	return cache, nil
}

func (m *MSAAD) syncRoles(roleGroups *cachedRoleGroups, aadUser *msaadUser, internalUserID UserId) (changed bool, err error) {
	nameInLogs := aadUser.profile.bestEmail()

	if m.config.Verbose {
		m.log.Infof("MSAAD syncRoles started for %s", nameInLogs)
	}

	permit, err := m.parent.GetPermit(internalUserID)
	if err != nil && !errors.Is(err, ErrIdentityPermitNotFound) {
		m.log.Errorf("MSAAD failed to fetch permit for user %v: %v", nameInLogs, err)
		return false, err
	}

	if permit == nil {
		permit = &Permit{}
	}

	// Figure out the existing groups that this user belongs to
	userGroupIDs, err := DecodePermit(permit.Roles)
	if err != nil {
		return false, err
	}

	groupsChanged := false
	userHasAnyIMQSPermission := false

	// identify unmapped groups
	removeIDs, _ := DecodePermit(make([]byte, 0))
	allowedIDs, _ := DecodePermit(make([]byte, 0))

	if m.config.Verbose {
		m.log.Infof("MSAAD empty role arrays constructed")
	}

	// get all mapped group ids
	for msaadGroupName, internalGroupName := range m.config.RoleToGroup {
		if m.config.Verbose {
			m.log.Infof("MSAAD checking all roles: %v -> %v", msaadGroupName, internalGroupName)
		}

		if internalGroup, ok := roleGroups.nameToGroup[internalGroupName]; ok {
			if m.config.Verbose {
				m.log.Infof("MSAAD add allowed ID for %v", internalGroupName)
			}
			allowedIDs = append(allowedIDs, internalGroup.ID)
		} else {
			if m.config.Verbose {
				m.log.Warnf("MSAAD skipping missing group %v", internalGroupName)
			}
		}
	}

	for _, groupName := range m.Config().DefaultRoles {
		if m.config.Verbose {
			m.log.Infof("MSAAD checking default roles: %v", groupName)
		}

		internalGroup, ok := roleGroups.nameToGroup[groupName]
		if !ok {
			// We've already logged an error about this, so here we just ignore it
			continue
		}
		if m.config.Verbose {
			m.log.Infof("MSAAD add allowed default ID for %v", groupName)
		}
		allowedIDs = append(allowedIDs, internalGroup.ID)
	}

	// now remove all IDs from groupID that is NOT in allowedIDs
	for _, groupID := range userGroupIDs {
		if allowedIDs.IndexOf(groupID) == -1 {
			if m.config.Verbose {
				m.log.Infof("MSAAD unmapped ID %v, add to remove list", groupID)
			}
			removeIDs = append(removeIDs, groupID)
		}
	}

	for _, id := range removeIDs {
		if idx := userGroupIDs.IndexOf(id); idx != -1 {
			m.log.Infof("MSAAD remove role %v for %v", roleGroups.idToGroupName(GroupIDU32(idx)), nameInLogs)
			userGroupIDs = removeFromGroupList(userGroupIDs, idx)
			groupsChanged = true
		}
	}

	// now synchronise with mapped items
	for aadRole, internalGroupName := range m.config.RoleToGroup {
		internalGroup, ok := roleGroups.nameToGroup[internalGroupName]
		if !ok {
			// We've already logged an error about this, so here we just ignore it
			continue
		}

		logPrefix := "MSAAD"
		if m.config.DryRun {
			logPrefix = "MSAAD dry-run:"
		}

		if aadUser.hasRoleByPrincipalDisplayName(aadRole, MatchTypeStandard) {
			// ensure that the user belongs to 'internalGroup'
			if indexInGroupInList(userGroupIDs, internalGroup.ID) == -1 {
				m.log.Infof(logPrefix+" grant %v to %v (from AAD role %v)", internalGroupName, nameInLogs, aadRole)
				if !m.config.DryRun {
					groupsChanged = true
					userGroupIDs = append(userGroupIDs, internalGroup.ID)
				}
			}
			userHasAnyIMQSPermission = true
		} else {
			// ensure that the user does not belong to 'internalGroup'
			if idx := userGroupIDs.IndexOf(internalGroup.ID); idx != -1 {
				m.log.Infof(logPrefix+" remove %v from %v (lacking AAD role %v)", internalGroupName, nameInLogs, aadRole)
				if !m.config.DryRun {
					groupsChanged = true
					userGroupIDs = removeFromGroupList(userGroupIDs, idx)
				}
			}
		}
	}

	// Add the DefaultRoles, where applicable in addition to the roles that were
	// found in the RoleToGroup configuration
	if userHasAnyIMQSPermission {
		for _, internalGroupName := range m.config.DefaultRoles {
			internalGroup, ok := roleGroups.nameToGroup[internalGroupName]
			if !ok {
				// Following the above logic, we have already logged this error
				continue
			}

			if indexInGroupInList(userGroupIDs, internalGroup.ID) == -1 {
				m.log.Infof("MSAAD grant default role %v to %v", internalGroupName, nameInLogs)
				userGroupIDs = append(userGroupIDs, internalGroup.ID)
				groupsChanged = true
			}
		}
		if groupsChanged {
			if m.config.Verbose {
				m.log.Infof("MSAAD granted default roles to %v", nameInLogs)
			}
		}
	} else {
		// REMOVE all default roles
		for _, internalGroupName := range m.config.DefaultRoles {
			internalGroup, ok := roleGroups.nameToGroup[internalGroupName]
			if !ok {
				// Following the above logic, we have already logged this error
				continue
			}

			if idx := userGroupIDs.IndexOf(internalGroup.ID); idx != -1 {
				m.log.Infof("MSAAD remove default role %v from %v (no MSADD roles)", internalGroupName, nameInLogs)
				userGroupIDs = removeFromGroupList(userGroupIDs, idx)
				groupsChanged = true
			}
		}
		if groupsChanged {
			m.log.Infof("MSAAD removed ALL default roles from %v (no MSADD roles)", nameInLogs)
		}
	}

	if groupsChanged && !m.config.DryRun {
		permit.Roles = EncodePermit(userGroupIDs)
		if err := m.parent.SetPermit(internalUserID, permit); err != nil {
			m.log.Errorf("MSAAD failed to set permit for user %v: %v", nameInLogs, err)
			return false, err
		}
	}

	return groupsChanged, nil
}

// populateAADRoles fetches the users roles and then appends the result to the users
// parameter as a native slice of msaadJSON objects. The roles of the individual
// user objects must be queried individually - which is the reason for
// separating this step from the fetching of the AAD users
func (m *MSAAD) populateAADRoles(users []*msaadUser) error {
	nThreads := numParallelFetchThreads(len(users))
	if m.config.Verbose {
		m.log.Infof("MSAAD populateAADRoles started...%d\n", len(users))
		m.log.Infof("MSAAD populateAADRoles : threads = %d\n", nThreads)
	}

	// partition 'users' into nThreads groups
	threadGroups := make([][]*msaadUser, nThreads)
	for i, u := range users {
		t := i % nThreads
		threadGroups[t] = append(threadGroups[t], u)
	}
	wg := sync.WaitGroup{}

	// errGlobal is protected by the following mutex
	var errGlobal error
	errLock := sync.Mutex{}

	startTime := time.Now()
	for i, threadGroupOuter := range threadGroups {
		if m.config.Verbose {
			m.log.Infof("MSAAD populateAADRoles : threadgroup# = %d\n", i)
		}
		wg.Add(1)
		go func(threadGroup []*msaadUser, i int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					s := GetStack()
					errGlobal = fmt.Errorf(fmt.Sprintf("%v\n%v\n", r, s))
				}
			}()
			for _, user := range threadGroup {
				if errGlobal != nil {
					m.log.Errorf("(%d) Global error detected in threadGroup-user loop...\n", i)
					break
				}
				if m.IsShuttingDown() {
					break
				}
				// Each of these calls is 0.2 seconds from my home network (South Africa to USA, presumably)... which is to be expected.
				// But that is the reason why we go to all this trouble to parallelize these fetches. If there are going to be, say, 10000
				// users on this AAD, then it certainly pays to parallelize these fetches.
				errLocal, quit := m.provider.GetUserAssignments(user, i)
				if errLocal != nil {
					errLock.Lock()
					errGlobal = errLocal
					errLock.Unlock()
				}
				if quit {
					return
				}
			}
		}(threadGroupOuter, i)
	}

	wg.Wait()
	if m.config.Verbose {
		m.log.Infof("MSAAD populateAADRoles waitgroup done...")
	}
	seconds := time.Now().Sub(startTime).Seconds()
	if len(users) != 0 {
		if m.numAADRoleFetches < 3 || m.numAADRoleFetches%20 == 0 || m.config.Verbose {
			m.log.Infof("Fetched %v AAD roles in %v seconds (%.2f seconds per fetch) (%v threads)", len(users), seconds, seconds*float64(nThreads)/float64(len(users)), nThreads)
		}
		m.numAADRoleFetches++
	}

	return errGlobal
}

func numParallelFetchThreads(nItems int) int {
	nThreads := nItems / 10
	if nThreads < 1 {
		nThreads = 1
	}
	if nThreads > 8 {
		nThreads = 8
	}
	return nThreads
}

func indexInGroupInList(list []GroupIDU32, g GroupIDU32) int {
	for i, x := range list {
		if x == g {
			return i
		}
	}
	return -1
}

func removeFromGroupList(list []GroupIDU32, i int) []GroupIDU32 {
	// since order of groups is not important, we can just swap in the last element, then pop
	// off the final element from the slice, which is much faster than creating a new slice every time.
	list[i] = list[len(list)-1]
	return list[:len(list)-1]
}

// checkSecretExpiry checks the MSAAD client secret for upcoming expiry
// and triggers notifications if it expires within the configured threshold.
func (m *MSAAD) checkSecretExpiry() {
	if m.config.SecretExpiryNotificationCallback == nil {
		return // No callback configured
	}

	if m.config.ClientSecretExpiryDate == nil {
		return // No expiry date configured
	}

	notificationDays := m.config.SecretExpiryNotificationDays
	if notificationDays == 0 {
		notificationDays = 14 // Default to 2 weeks
	}

	now := time.Now()
	threshold := now.Add(time.Duration(notificationDays) * 24 * time.Hour)

	if m.config.ClientSecretExpiryDate.Before(threshold) && m.config.ClientSecretExpiryDate.After(now) {
		// Calculate days based on date difference, not time difference
		nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		expiryDate := time.Date(m.config.ClientSecretExpiryDate.Year(), m.config.ClientSecretExpiryDate.Month(), m.config.ClientSecretExpiryDate.Day(), 0, 0, 0, 0, m.config.ClientSecretExpiryDate.Location())
		daysUntilExpiry := int(expiryDate.Sub(nowDate).Hours() / 24)
		
		m.config.SecretExpiryNotificationCallback("MSAAD", daysUntilExpiry, *m.config.ClientSecretExpiryDate)
		
		if m.config.Verbose {
			m.log.Warnf("MSAAD client secret expires in %d days (%s)", 
				daysUntilExpiry, m.config.ClientSecretExpiryDate.Format(time.RFC3339))
		}
	}
}
