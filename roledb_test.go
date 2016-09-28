package authaus

import (
	"testing"
)

// There are a whole lot more tests that belong here, such as stressing the concurrency of the group cache,
// verifying the robustness of the permissions decoder/encoder, etc.

const (
	permX PermissionU16 = 1
	permY PermissionU16 = 2
)

const (
	groupNameXandY = "groupXandY"
	groupNameY     = "groupY"
)

func setup1_withRoleDB(t *testing.T) *Central {
	c := setup(t)

	groupY := &AuthGroup{}
	groupY.Name = groupNameY
	groupY.AddPerm(permY)
	c.GetRoleGroupDB().InsertGroup(groupY)

	groupXandY := &AuthGroup{}
	groupXandY.Name = groupNameXandY
	groupXandY.AddPerm(permX)
	groupXandY.AddPerm(permY)
	c.GetRoleGroupDB().InsertGroup(groupXandY)

	return c
}

func TestAuthRoleDB(t *testing.T) {
	c := setup1_withRoleDB(t)
	roleGroupDBCache := c.roleGroupDB.(*RoleGroupCache)

	// wipe the cache
	roleGroupDBCache.reset()

	// fetch a single group
	if group, err := c.GetRoleGroupDB().GetByName(groupNameXandY); err != nil {
		t.Errorf("RoleGroup.GetByName failed: %v", err)
	} else if !(len(group.PermList) == 2 && group.HasPerm(permX) && group.HasPerm(permY)) {
		t.Errorf("groupXandY not correct")
	}

	fetchAllGroups := func() {
		for i := 0; i < 1000; i++ {
			roleGroupDBCache.lockAndReset()
			if all, err := c.GetRoleGroupDB().GetGroups(); err != nil {
				t.Errorf("GetGroups failed: %v", err)
			} else if len(all) != 2 {
				t.Errorf("GetGroups did not return expected number of groups")
			}
		}
	}
	go fetchAllGroups()
	go fetchAllGroups()
}
