package authaus

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestLDAPUserDiffSame(t *testing.T) {
	// Test the user diff function with two identical users
	userBefore := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              time.Now(),
		CreatedBy:            UserIdLDAPMerge,
		Modified:             time.Now(),
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: time.Now(),
		AccountLocked:        false,
	}
	now := time.Now()
	userAfter := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              now,
		CreatedBy:            UserIdLDAPMerge,
		Modified:             now,
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: now,
		AccountLocked:        false,
	}
	diff, e := userInfoDiff(userBefore, userAfter)
	assert.Nil(t, e, "Error should be nil")
	assert.Empty(t, diff, "Diff should be empty")
}

func TestLDAPUserDiffDiff(t *testing.T) {
	// Test all diff on all fields and exclusion of ignored fields
	userBefore := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              time.Now(),
		CreatedBy:            UserIdLDAPMerge,
		Modified:             time.Now(),
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: time.Now(),
		AccountLocked:        false,
	}
	userAfter := AuthUser{
		Email:                "john@doe.com1",
		Username:             "JohnDoe1",
		Firstname:            "John1",
		Lastname:             "Doe1",
		Mobilenumber:         "080 555 55551",
		Telephonenumber:      "021 888 55515",
		Remarks:              "Before comment1",
		Created:              time.Now().Add(time.Minute),
		CreatedBy:            UserIdAdministrator,
		Modified:             time.Now().Add(time.Minute),
		ModifiedBy:           UserIdAdministrator,
		Type:                 UserTypeLDAP,
		Archived:             true,
		InternalUUID:         "3342-3342-3342-33421",
		ExternalUUID:         "4438-4438-4438-44381",
		PasswordModifiedDate: time.Now().Add(time.Minute),
		AccountLocked:        true,
	}
	excludeFields := []string{"created", "createdBy", "modified", "modifiedBy", "passwordModifiedDate"}
	diff, e := userInfoDiff(userBefore, userAfter)
	assert.Nil(t, e, "Error should be nil")
	assert.NotEmpty(t, diff)
	for _, field := range excludeFields {
		assert.NotContains(t, diff, field, "Field %v should not be in the diff", field)
	}
	t.Logf("User diff: \n%v", diff)
}
