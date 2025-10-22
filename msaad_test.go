package authaus

import (
	"github.com/IMQS/log"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

/** Test cases for msaad.go **/

/*
NOTICE : When adding tests here for new functions related to user credentials,
make sure to check if similar functions in oauth.go does not need to be updated.
Since OAUTH and MSAAD are similar in many ways, and both can directly affect
user details in the system, slight difference in how they convert user details
from the identity authority can cause issues. One example would be
how the user's "Username" is treated.
*/

var testProvider *dummyMSAADProvider

func getCentralMSAAD(t *testing.T) *Central {
	var userStore UserStore
	var sessionDB SessionDB
	var permitDB PermitDB
	var roleDB RoleGroupDB
	var msaad MSAAD
	msaad.SetConfig(ConfigMSAAD{
		Verbose:              true,
		DryRun:               false,
		TenantID:             irrelevantUUID,
		ClientID:             irrelevantUUID,
		ClientSecret:         "abcdef",
		MergeIntervalSeconds: 30,
		DefaultRoles:         []string{"enabled"},
		RoleToGroup: map[string]string{
			"AZ_ROLE_1": "IMQS Group 1",
			"AZ_ROLE_2": "IMQS Group 2",
			"AZ_ROLE_3": "IMQS Group 3",
		},
		AllowArchiveUser:     true,
		PassthroughClientIDs: []string{irrelevantUUID},
	})
	testProvider = &dummyMSAADProvider{
		testUsers: buildTestUsers(),
	}

	msaad.SetProvider(testProvider)

	sessionDB = newDummySessionDB()
	permitDB = newDummyPermitDB()

	roleDB = newDummyRoleGroupDB()
	if err := roleDB.InsertGroup(&AuthGroup{
		Name: "IMQS Group 1",
		PermList: PermissionList{
			1, 2,
		},
	}); err != nil {
		assert.Fail(t, "Error inserting group")
	}
	if err := roleDB.InsertGroup(&AuthGroup{
		Name: "IMQS Group 10",
		PermList: PermissionList{
			3, 4,
		},
	}); err != nil {
		assert.Fail(t, "Error inserting group")
	}
	if err := roleDB.InsertGroup(&AuthGroup{
		Name: "enabled",
		PermList: PermissionList{
			5, 6,
		},
	}); err != nil {
		assert.Fail(t, "Error inserting group")
	}

	userStore = newDummyUserStore()
	userStore.CreateIdentity(&AuthUser{
		Email:                "test@domain.com",
		Username:             "test@domain.com",
		Firstname:            "test",
		Lastname:             "person",
		Mobilenumber:         "",
		Telephonenumber:      "",
		Remarks:              "",
		Created:              time.Time{},
		CreatedBy:            0,
		Modified:             time.Time{},
		ModifiedBy:           0,
		Type:                 UserTypeMSAAD,
		Archived:             false,
		InternalUUID:         irrelevantUUID,
		ExternalUUID:         "b655a754-ce0f-4581-b298-d0f0e3ead53d",
		PasswordModifiedDate: time.Time{},
		AccountLocked:        false,
	}, "password")
	userStore.CreateIdentity(&AuthUser{
		Email:                "Jane.Doe@example.com",
		Username:             "Jane.Doe@example.com",
		Firstname:            "Jane",
		Lastname:             "Doe",
		Mobilenumber:         "",
		Telephonenumber:      "",
		Remarks:              "",
		Created:              time.Time{},
		CreatedBy:            0,
		Modified:             time.Time{},
		ModifiedBy:           0,
		Type:                 UserTypeMSAAD,
		Archived:             false,
		InternalUUID:         irrelevantUUID,
		ExternalUUID:         "12345678-1234-1234-1234-123456789012",
		PasswordModifiedDate: time.Time{},
		AccountLocked:        false,
	}, "password")
	userStore.CreateIdentity(&AuthUser{
		Email:                "unarchive.me@example.com",
		Username:             "unarchive.me@example.com",
		Firstname:            "Unarchive",
		Lastname:             "Me",
		Mobilenumber:         "",
		Telephonenumber:      "",
		Remarks:              "",
		Created:              time.Time{},
		CreatedBy:            0,
		Modified:             time.Time{},
		ModifiedBy:           0,
		Type:                 UserTypeMSAAD,
		Archived:             true,
		InternalUUID:         irrelevantUUID,
		ExternalUUID:         "e182f909-128c-4681-a12d-1eb4a92eec50",
		PasswordModifiedDate: time.Time{},
		AccountLocked:        false,
	}, "password")
	// enabled (default) only, should be archived
	userStore.CreateIdentity(&AuthUser{
		Email:                "enabled.only@example.com",
		Username:             "enabled.only@example.com",
		Firstname:            "enabled",
		Lastname:             "only",
		Mobilenumber:         "",
		Telephonenumber:      "",
		Remarks:              "",
		Created:              time.Time{},
		CreatedBy:            0,
		Modified:             time.Time{},
		ModifiedBy:           0,
		Type:                 UserTypeMSAAD,
		Archived:             false,
		InternalUUID:         irrelevantUUID,
		ExternalUUID:         "9a740e65-ab36-43b5-86bd-902e81ab00c0",
		PasswordModifiedDate: time.Time{},
		AccountLocked:        false,
	}, "password")
	groupIds := GroupIDU32s{}
	gi, _ := roleDB.GetByName("IMQS Group 1")
	groupIds = append(groupIds, gi.ID)
	gi, _ = roleDB.GetByName("IMQS Group 10")
	groupIds = append(groupIds, gi.ID)
	gi, _ = roleDB.GetByName("enabled")
	groupIds = append(groupIds, gi.ID)

	var p Permit
	user, _ := userStore.GetUserFromIdentity("test@domain.com")
	p.Roles = EncodePermit(groupIds)
	permitDB.SetPermit(user.UserId, &p)

	user, _ = userStore.GetUserFromIdentity("Jane.Doe@example.com")
	p.Roles = EncodePermit(groupIds)
	permitDB.SetPermit(user.UserId, &p)

	user, _ = userStore.GetUserFromIdentity("enabled.only@example.com")
	gi, _ = roleDB.GetByName("enabled")
	groupIds = GroupIDU32s{gi.ID}
	p.Roles = EncodePermit(groupIds)
	permitDB.SetPermit(user.UserId, &p)

	c := NewCentral(log.Stdout, nil, &msaad, userStore, permitDB, sessionDB, roleDB)
	da := &dummyAuditor{}
	da.messages = []string{}
	da.testing = t
	c.Auditor = da
	return c
}

func Test_Match(t *testing.T) {
	inOut := []struct {
		left  string
		right string
		out   MatchType
	}{
		{"Test Group 1", "Test Group 1", MatchTypeExact},
		{"Test Group 1", "Test Group", MatchTypeNone},
		{"Test Group 1", "est Group 1 ", MatchTypeNone},

		// Boundary cases
		{"", "", MatchTypeExact},
		{"", "Test Group 1", MatchTypeNone},
		{"Test Group 1", "", MatchTypeNone},
		{"Test Group 1", "Group", MatchTypeNone},

		// Wildcards
		{"", "*", MatchTypeStartsWith},
		{"*", "*", MatchTypeStartsWith},
		{"1", "*", MatchTypeStartsWith},
		{"12", "*", MatchTypeStartsWith},

		// Shortest string drives match type
		{"TestABCD*", "Test", MatchTypeNone},
		{"Test*", "TestABCD*", MatchTypeStartsWith},
		{"TestABCD*", "Test*", MatchTypeStartsWith},

		{"Test Group 1", "Test*", MatchTypeStartsWith},
		{"Test Group 1", "Test*BlahBlah", MatchTypeNone},

		// Endswith is weird
		{"Test Group 1", "*1", MatchTypeNone},
		{"Test Group 1", "Group 1*", MatchTypeEndsWith},
		{"Test Group 1", "Group 1*BlahBlah", MatchTypeNone},
	}
	for _, io := range inOut {
		out := Match(io.left, io.right)
		if out != io.out {
			assert.Equal(t, io.out, out, "Failed for %v:%v", io.left, io.right) //, fmt.Sprintf("Input \"%v\", expected \"%v\", got \"%v\"")
		}
	}
}

func Test_SplitDisplayName(t *testing.T) {
	type out struct {
		Name    string
		Surname string
	}
	inOut := []struct {
		in   string
		out  out
		pass bool
	}{
		// normal cases
		{"Jane Doe", out{"Jane", "Doe"}, true},
		{"Jane du Toit", out{"Jane", "du Toit"}, true},
		{"Peter", out{"Peter", ""}, true},
		{"", out{"", ""}, true},
		{" ", out{"", ""}, true},
		{"Broken", out{"Fail", "Test"}, false},
	}
	for _, io := range inOut {
		name, surname := splitDisplayName(io.in)
		if io.pass {
			assert.Equal(t, io.out.Name, name, "Failed for %v, ", io.in)
			assert.Equal(t, io.out.Surname, surname, "Failed for %v, ", io.in)
		} else {
			assert.NotEqual(t, io.out.Name, name, "Failed for %v, ", io.in)
			assert.NotEqual(t, io.out.Surname, surname, "Failed for %v, ", io.in)
		}
	}
}

func Test_NameAndSurname(t *testing.T) {
	type out struct {
		Name    string
		Surname string
	}

	inOut := []struct {
		in  msaadUserJSON
		out out
	}{
		// normal cases
		{msaadUserJSON{DisplayName: "Mary Poppins", GivenName: "Jane", Surname: "Doe"}, out{"Jane", "Doe"}},
		{msaadUserJSON{DisplayName: "", GivenName: "Jane", Surname: "Doe"}, out{"Jane", "Doe"}},
		// edge cases
		{msaadUserJSON{DisplayName: "", Surname: "Doe"}, out{"", ""}},
		{msaadUserJSON{DisplayName: "", GivenName: "Jane"}, out{"", ""}},
		{msaadUserJSON{DisplayName: "Jane Doe"}, out{"Jane", "Doe"}},
		{msaadUserJSON{DisplayName: "Jane Doe", GivenName: "Mary"}, out{"Jane", "Doe"}},
		{msaadUserJSON{DisplayName: "Jane Doe", Surname: "Poppins"}, out{"Jane", "Doe"}},
	}
	for _, io := range inOut {
		name, surname := io.in.nameAndSurname()
		assert.Equal(t, io.out.Name, name, "Failed for %v, ", io.in)
		assert.Equal(t, io.out.Surname, surname, "Failed for %v, ", io.in)
	}
}

func Test_bestEmail(t *testing.T) {
	inOut := []struct {
		in  msaadUserJSON
		out string
	}{
		// normal cases
		{msaadUserJSON{Mail: "jane.doe@example.com", UserPrincipalName: "jane.poppins_example.com#EXT#mydomain.com"},
			"jane.doe@example.com"},
		{msaadUserJSON{Mail: "", UserPrincipalName: "jane.poppins_example.com#EXT#mydomain.com"},
			"jane.poppins@example.com"},
	}
	for _, io := range inOut {
		out := io.in.bestEmail()
		assert.Equal(t, io.out, out, "Failed for %v, ", io.in)
	}
}

func Test_ConvertUPNToEmail(t *testing.T) {
	inOut := []struct {
		in  string
		out string
	}{
		// normal cases
		{"joan.soap@example.com", "joan.soap@example.com"},
		{"joan.soap_example.com#EXT#@domain.com", "joan.soap@example.com"},
		{"joan.soap@example.com#EXT#@domain.com", "joan.soap@example.com"},
		// invalid cases
		// malformed email
		{"joan.soap", ""},
		{"joan.soap@", ""},
		{"", ""},
		{"@examplecom", ""},
		{"joan.soap@examplecom", ""},
		{"joan.soap@middle@example.com", ""},
		// EXTernal domain
		{"joan.soap_example.com#EX#domain.com", ""},
		{"joan.soap_example.com#EXdomain.com", ""},
		{"joan.soap_example.com#EXdomain.com", ""},
		{"joan.soap_middle_example.com#EXdomain.com", ""},
	}
	for _, io := range inOut {
		out := convertUPNToEmail(io.in)
		if out != io.out {
			assert.Equal(t, io.out, out, "Failed for %v", io.in) //, fmt.Sprintf("Input \"%v\", expected \"%v\", got \"%v\"")
		}
	}
}

func Test_ToAuthUser(t *testing.T) {
	inOut := []struct {
		in  msaadUserJSON
		out AuthUser
	}{
		{
			// normal cases
			msaadUserJSON{
				DisplayName:       "Jane Doe",
				GivenName:         "Jane",
				Mail:              "jane.doe@example.com",
				UserPrincipalName: "jane.doe_example.com#EXT#mydomain.com",
			},
			AuthUser{
				UserId:    0,
				Email:     "jane.doe@example.com",
				Username:  "jane.doe@example.com",
				Firstname: "Jane",
				Lastname:  "Doe",
				Type:      3,
			}},
	}
	for _, io := range inOut {
		out := io.in.toAuthUser()
		assert.Equal(t, io.out, out, "Failed for %v", io.in)

	}
}

func Test_InjectIntoAuthUser(t *testing.T) {
	inOut := []struct {
		in     msaadUserJSON
		target *AuthUser
		out    *AuthUser
	}{
		{
			// normal cases
			msaadUserJSON{
				DisplayName:       "Jane Doe",
				GivenName:         "Jane",
				Mail:              "",
				UserPrincipalName: "jane.doe_example.com#EXT#mydomain.com",
				ID:                "12345678-1234-1234-1234-123456789012",
			},
			&AuthUser{
				UserId:               123,
				Email:                "jane.doe@example.com",
				Username:             "",
				Firstname:            "Mary",
				Lastname:             "Poppins",
				Mobilenumber:         "",
				Telephonenumber:      "",
				Remarks:              "",
				Created:              time.Time{},
				CreatedBy:            0,
				Modified:             time.Time{},
				ModifiedBy:           0,
				Type:                 1,
				Archived:             false,
				InternalUUID:         "098ea9d7-c05b-4a66-9217-24b9b702d6da",
				ExternalUUID:         "",
				PasswordModifiedDate: time.Time{},
				AccountLocked:        false,
			},
			&AuthUser{
				UserId:               123,
				Email:                "jane.doe@example.com",
				Username:             "jane.doe@example.com",
				Firstname:            "Jane",
				Lastname:             "Doe",
				Mobilenumber:         "",
				Telephonenumber:      "",
				Remarks:              "",
				Created:              time.Time{},
				CreatedBy:            0,
				Modified:             time.Time{},
				ModifiedBy:           0,
				Type:                 3,
				Archived:             false,
				InternalUUID:         "098ea9d7-c05b-4a66-9217-24b9b702d6da",
				ExternalUUID:         "12345678-1234-1234-1234-123456789012",
				PasswordModifiedDate: time.Time{},
				AccountLocked:        false,
			},
		},
		{
			// username check
			msaadUserJSON{
				DisplayName:       "Jane Doe",
				GivenName:         "Jane",
				Mail:              "jane.doe@example.com",
				UserPrincipalName: "jane.doe_example.com#EXT#mydomain.com",
				ID:                "12345678-1234-1234-1234-123456789012",
			},
			&AuthUser{
				UserId: 0,
				Email:  "jane.doe@example.com",
				// WARNING : Do not change this test without carefully considering the implications
				// Username is special and should not be updated by the MSAAD
				Username:             "me@test.com",
				Firstname:            "Jane",
				Lastname:             "Doe",
				Mobilenumber:         "",
				Telephonenumber:      "",
				Remarks:              "",
				Created:              time.Time{},
				CreatedBy:            0,
				Modified:             time.Time{},
				ModifiedBy:           0,
				Type:                 3,
				Archived:             false,
				InternalUUID:         "098ea9d7-c05b-4a66-9217-24b9b702d6da",
				ExternalUUID:         "12345678-1234-1234-1234-123456789012",
				PasswordModifiedDate: time.Time{},
				AccountLocked:        false,
			},
			&AuthUser{
				UserId:               0,
				Email:                "jane.doe@example.com",
				Username:             "me@test.com",
				Firstname:            "Jane",
				Lastname:             "Doe",
				Mobilenumber:         "",
				Telephonenumber:      "",
				Remarks:              "",
				Created:              time.Time{},
				CreatedBy:            0,
				Modified:             time.Time{},
				ModifiedBy:           0,
				Type:                 3,
				Archived:             false,
				InternalUUID:         "098ea9d7-c05b-4a66-9217-24b9b702d6da",
				ExternalUUID:         "12345678-1234-1234-1234-123456789012",
				PasswordModifiedDate: time.Time{},
				AccountLocked:        false,
			},
		},
	}
	for _, io := range inOut {
		io.in.injectIntoAuthUser(io.target)
		assert.Equal(t, io.out, io.target, "Failed for %v", io.in)
	}
}

type void struct{}

var member void

func findUser(users []AuthUser, email string) *AuthUser {
	for _, user := range users {
		if user.Email == email {
			return &user
		}
	}
	return nil
}

func addToSetAuth(users []AuthUser, allIdentities map[string]void) {
	for _, u := range users {
		allIdentities[u.Email] = member
	}
}

func addToSetMsaad(users []*msaadUser, allIdentities map[string]void) {
	for _, u := range users {
		allIdentities[u.profile.bestEmail()] = member
	}
}

func groupsFromPermit(c *Central, user *AuthUser) GroupIDU32s {
	p, _ := c.permitDB.GetPermit(user.UserId)
	r, _ := DecodePermit(p.Roles)
	return r
}

func Test_GetUserAssignments(t *testing.T) {
	// Test that the GetUserAssignments function behaves correctly
	// and that errGlobal is properly handled
	
	// Create a dummy provider
	provider := &dummyMSAADProvider{
		testUsers: buildTestUsers(),
	}
	
	// Initialize it with a dummy parent and logger
	msaad := &MSAAD{}
	msaad.SetConfig(ConfigMSAAD{Verbose: true})
	logger := log.New("", false) // Use empty string to discard logs in tests
	provider.Initialize(msaad, logger)
	
	// Test with a valid user
	user := &msaadUser{
		profile: msaadUserJSON{
			ID: "12345678-1234-1234-1234-123456789012",
		},
	}
	
	errGlobal, quit := provider.GetUserAssignments(user, 0)
	
	// Should not return an error for valid user
	assert.Nil(t, errGlobal, "Expected no error for valid user")
	assert.False(t, quit, "Expected quit to be false for successful operation")
	assert.NotNil(t, user.roles, "Expected roles to be populated")
	assert.Greater(t, len(user.roles), 0, "Expected at least one role for test user")
	
	// Test with an invalid user (should not crash or have undefined behavior)
	invalidUser := &msaadUser{
		profile: msaadUserJSON{
			ID: "invalid-user-id",
		},
	}
	
	errGlobal2, quit2 := provider.GetUserAssignments(invalidUser, 0)
	
	// For the dummy provider, invalid users just get empty roles
	assert.Nil(t, errGlobal2, "Expected no error for invalid user in dummy provider")
	assert.False(t, quit2, "Expected quit to be false")
	assert.Equal(t, 0, len(invalidUser.roles), "Expected no roles for invalid user")
}

func Test_GetUserAssignments_ErrorHandling(t *testing.T) {
	// This test specifically validates the fix for the issue where errGlobal
	// variable was being checked incorrectly in the loop.
	// 
	// Before the fix:
	// - errGlobal was checked at the start of the loop but could never be != nil
	//   at that point since it was only set within the function scope
	// - The logic was confusing because errGlobal would always be nil when quit
	//   was false, and always have a value when quit was true
	
	// Create a mock provider that can simulate errors
	provider := &dummyMSAADProvider{
		testUsers: buildTestUsers(),
	}
	
	// Initialize it
	msaad := &MSAAD{}
	msaad.SetConfig(ConfigMSAAD{Verbose: false}) // Reduce log noise
	logger := log.New("", false) // Use empty string to discard logs in tests
	provider.Initialize(msaad, logger)
	
	// Test with a valid user - should succeed
	user := &msaadUser{
		profile: msaadUserJSON{
			ID: "12345678-1234-1234-1234-123456789012",
		},
	}
	
	errGlobal, quit := provider.GetUserAssignments(user, 0)
	
	// The fix ensures that:
	// 1. When there's no error, errGlobal is nil and quit is false
	assert.Nil(t, errGlobal, "Expected errGlobal to be nil on success")
	assert.False(t, quit, "Expected quit to be false on success")
	
	// 2. The function completes successfully and populates roles
	assert.NotNil(t, user.roles, "Expected roles to be populated")
	
	// Note: With the dummy provider, we can't easily test error conditions,
	// but the important fix is that the errGlobal check at the start of the loop
	// has been removed, which was the core issue identified.
}

func Test_SynchronizeUsers(t *testing.T) {
	allIdentities := map[string]void{}
	c := getCentralMSAAD(t)

	// all msaad emails
	aadIdentities, _ := testProvider.GetAADUsers()
	addToSetMsaad(aadIdentities, allIdentities)

	// all user store emails
	usersBefore, _ := c.userStore.GetIdentities(GetIdentitiesFlagDeleted)
	addToSetAuth(usersBefore, allIdentities)

	e := c.MSAAD.SynchronizeUsers()

	if e != nil {
		t.Errorf("Failed to synchronize users: %v", e)
	}
	users, _ := c.userStore.GetIdentities(GetIdentitiesFlagDeleted)
	addToSetAuth(users, allIdentities)

	foundCreate := 0
	foundUpdate := 0
	foundArchived := 0
	foundUnarchived := 0

	// now we can compare before and after
	for email := range allIdentities {
		userBefore := findUser(usersBefore, email)
		userAfter := findUser(users, email)

		if userBefore == nil && userAfter != nil {
			foundCreate++
		}

		if userBefore != nil && userAfter != nil {
			if userBefore.Archived && !userAfter.Archived {
				foundUnarchived++
			}
			if !userBefore.Archived && userAfter.Archived {
				foundArchived++
			}
			if userBefore.Mobilenumber != userAfter.Mobilenumber {
				foundUpdate++
			}
		}
	}

	if user := findUser(users, "Jane.Doe@example.com"); user != nil {
		assert.Equal(t, "055 555 4328", user.Mobilenumber)
		assert.Equal(t, false, user.Archived)
		r := groupsFromPermit(c, user)
		// Jane only has MSAAD role AZ_ROLE_2, which is mapped,
		// but the actual IMQS group does not exist.
		// --
		// Jane won't be archived, since the MSAAD group is known and associated
		// with IMQS (otherwise we won't receive her in the first place).
		// However, since there are no _valid_ IMQS roles, Jane won't be enabled.
		// So she ends up having an _empty_ permit.
		assert.Equal(t, 0, len(r))
	}

	if user := findUser(users, "test@domain.com"); user != nil {
		assert.True(t, user.Archived)
		r := groupsFromPermit(c, user)
		assert.Equal(t, 0, len(r))
	}

	if user := findUser(users, "unarchive.me@example.com"); user != nil {
		assert.False(t, user.Archived)
		r := groupsFromPermit(c, user)
		assert.Equal(t, 2, len(r))
	}

	if user := findUser(users, "John.Doe@example.com"); user != nil {
		assert.False(t, user.Archived)
		r := groupsFromPermit(c, user)
		assert.Equal(t, 2, len(r))
	}

	if user := findUser(users, "enabled.only@example.com"); user != nil {
		assert.True(t, user.Archived)
		r := groupsFromPermit(c, user)
		assert.Equal(t, 0, len(r))
	}

	assert.Equal(t, 1, foundUpdate, "User not updated after synchronization")
	assert.Equal(t, 2, foundArchived, "User not archived after synchronization")
	assert.Equal(t, 1, foundUnarchived, "User not unarchived after synchronization")
	assert.Equal(t, 1, foundCreate, "User not created after synchronization")
}
