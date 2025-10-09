package authaus

import "github.com/IMQS/log"

const irrelevantUUID = "99999999-9999-9999-9999-999999999999"

type dummyMSAADProvider struct {
	parent    MSAADInterface
	log       *log.Logger
	testUsers map[string]*testUser
}

type testUser struct {
	user  *msaadUserJSON
	roles []*msaadRoleJSON
}

func buildTestUsers() map[string]*testUser {
	return map[string]*testUser{
		"12345678-1234-1234-1234-123456789012": {
			user: &msaadUserJSON{
				DisplayName:       "Jane Doe",
				GivenName:         "Jane",
				Mail:              "Jane.Doe@example.com",
				Surname:           "Doe",
				MobilePhone:       "055 555 4328",
				UserPrincipalName: "Jane.Doe@example.com",
				ID:                "12345678-1234-1234-1234-123456789012",
			},
			roles: []*msaadRoleJSON{
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "Unknown Group 1",
					PrincipalID:          "",
					PrincipalType:        "Group",
					CreatedDateTime:      "2024-05-01T00:00:00Z",
					ResourceDisplayName:  "Unknown Group 1",
				},
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "AZ_ROLE_2",
					PrincipalID:          "",
					PrincipalType:        "Group",
					ResourceDisplayName:  "AZ_ROLE_2",
				},
			},
		},
		"81e36e95-19f4-4c8b-ad09-97123f7bb8ab": {
			user: &msaadUserJSON{
				DisplayName:       "John Doe",
				GivenName:         "John",
				Mail:              "John.Doe@example.com",
				Surname:           "Doe",
				MobilePhone:       "123 456 7890",
				UserPrincipalName: "John.Doe@example.com",
				ID:                "81e36e95-19f4-4c8b-ad09-97123f7bb8ab",
			},
			roles: []*msaadRoleJSON{
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "Unknown Group 1",
					PrincipalID:          "",
					PrincipalType:        "Group",
					CreatedDateTime:      "2024-05-01T00:00:00Z",
					ResourceDisplayName:  "Unknown Group 1",
				},
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "AZ_ROLE_1",
					PrincipalID:          "",
					PrincipalType:        "Group",
					ResourceDisplayName:  "AZ_ROLE_1",
				},
			},
		},
		"e182f909-128c-4681-a12d-1eb4a92eec50": {
			user: &msaadUserJSON{
				DisplayName:       "Unarchive Me",
				GivenName:         "Unarchive",
				Mail:              "unarchive.me@example.com",
				Surname:           "Me",
				MobilePhone:       "",
				UserPrincipalName: "unarchive.me@example.com",
				ID:                "e182f909-128c-4681-a12d-1eb4a92eec50",
			},
			roles: []*msaadRoleJSON{
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "Unknown Group 1",
					PrincipalID:          "",
					PrincipalType:        "Group",
					CreatedDateTime:      "2024-05-01T00:00:00Z",
					ResourceDisplayName:  "Unknown Group 1",
				},
				{
					ID:                   irrelevantUUID,
					PrincipalDisplayName: "AZ_ROLE_1",
					PrincipalID:          "",
					PrincipalType:        "Group",
					ResourceDisplayName:  "AZ_ROLE_1",
				},
			},
		},
		"9a740e65-ab36-43b5-86bd-902e81ab00c0": {
			user: &msaadUserJSON{
				DisplayName:       "Enabled",
				GivenName:         "Enabled Only",
				Mail:              "enabled.only@example.com",
				Surname:           "Only",
				MobilePhone:       "",
				UserPrincipalName: "enabled.only@example.com",
				ID:                "9a740e65-ab36-43b5-86bd-902e81ab00c0",
			},
			roles: []*msaadRoleJSON{},
		},
	}
}

func (d *dummyMSAADProvider) IsShuttingDown() bool {
	return d.parent.IsShuttingDown()
}

func (d *dummyMSAADProvider) Initialize(parent MSAADInterface, log *log.Logger) error {
	d.parent = parent
	d.log = log
	return nil
}

func (d *dummyMSAADProvider) Parent() MSAADInterface {
	return d.parent
}

func (d *dummyMSAADProvider) GetAADUsers() ([]*msaadUser, error) {
	tu := buildTestUsers()
	var msaadUsers []*msaadUser

	for _, v := range tu {
		msaadUsers = append(msaadUsers, &msaadUser{
			profile: *v.user,
		})
	}
	return msaadUsers, nil
}

func (d *dummyMSAADProvider) GetUserAssignments(user *msaadUser, i int) (errGlobal error, quit bool) {
	tu := buildTestUsers()
	if v, ok := tu[user.profile.ID]; ok {
		user.roles = v.roles
	}
	return nil, false
}

func (d *dummyMSAADProvider) GetAppRoles() (rolesList []string, errGlobal error, quit bool) {
	return []string{"AZ_ROLE_1", "AZ_ROLE_2"}, nil, false
}
