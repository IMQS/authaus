package authaus

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

// There are a whole lot more tests that belong here, such as stressing the concurrency of the group cache,
// verifying the robustness of the permissions decoder/encoder, etc.

const (
	permX PermissionU16 = 1
	permY PermissionU16 = 2
	permZ PermissionU16 = 3
)

const (
	groupNameXandY = "groupXandY"
	groupNameY     = "groupY"
	groupNameZ     = "groupZ"
)

func setup1_withRoleDB(t *testing.T) *Central {
	c := setup(t)

	groupY := &AuthGroup{}
	groupY.Name = groupNameY
	groupY.AddPerm(permY)
	e := c.GetRoleGroupDB().InsertGroup(groupY)
	if e != nil {
		assert.Fail(t, "Could not add groups.")
	}
	groupXandY := &AuthGroup{}
	groupXandY.Name = groupNameXandY
	groupXandY.AddPerm(permX)
	groupXandY.AddPerm(permY)
	e = c.GetRoleGroupDB().InsertGroup(groupXandY)
	if e != nil {
		assert.Fail(t, "Could not add groups.")
	}
	return c
}

func setup1_AddRoleGroup(t *testing.T, c *Central) {
	groupZ := &AuthGroup{}
	groupZ.Name = groupNameZ
	groupZ.AddPerm(permZ)
	e := c.GetRoleGroupDB().InsertGroup(groupZ)
	if e != nil {
		assert.Fail(t, "Could not add groups.")
	}
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

	fetchAllGroups := func(w *sync.WaitGroup) {
		for i := 0; i < 1000; i++ {
			roleGroupDBCache.lockAndReset()
			if all, err := c.GetRoleGroupDB().GetGroups(); err != nil {
				t.Errorf("GetGroups failed: %v", err)
			} else if len(all) != 2 {
				t.Errorf("GetGroups did not return expected number of groups")
			}
		}
		w.Done()
	}
	w := sync.WaitGroup{}
	w.Add(2)
	go fetchAllGroups(&w)
	go fetchAllGroups(&w)
	w.Wait()
}

func TestAuthRoleDB_MissingGroups(t *testing.T) {
	c := setup1_withRoleDB(t)
	roleGroupDBCache := c.roleGroupDB.(*RoleGroupCache)

	idu32s := make([]GroupIDU32, 3)
	idu32s[0] = GroupIDU32(1)
	idu32s[1] = GroupIDU32(2)
	idu32s[2] = GroupIDU32(3)
	pbyte := EncodePermit(idu32s)
	plist, e := PermitResolveToList(pbyte, roleGroupDBCache)
	fmt.Printf("Permissions: %v\n", plist)
	assert.NotNil(t, e, "An error should be returned for the missing group")
	assert.Equal(t, 2, len(plist))
}

func TestAuthRoleDB_GroupIdsToNames(t *testing.T) {
	c := setup1_withRoleDB(t)

	// Normal case
	idu32s := make([]GroupIDU32, 2)
	idu32s[0] = GroupIDU32(1)
	idu32s[1] = GroupIDU32(2)

	cache := map[GroupIDU32]string{}
	plist, e := GroupIDsToNames(idu32s, c.roleGroupDB, cache)

	fmt.Printf("Permissions: %v\n", plist)
	assert.Nil(t, e, "Error is not expected.")
	assert.Equal(t, 2, len(plist), "Invalid nr of permissions in list.")
	assert.Equal(t, 2, len(cache), "Invalid nr of cache items in list.")

	// Missing group
	idu32s = make([]GroupIDU32, 3)
	idu32s[0] = GroupIDU32(1)
	idu32s[1] = GroupIDU32(2)
	idu32s[2] = GroupIDU32(3)
	plist, e = GroupIDsToNames(idu32s, c.roleGroupDB, cache)

	fmt.Printf("Permissions: %v\n", plist)
	assert.NotNil(t, e, "Error is expected.")
	assert.Equal(t, 2, len(plist), "Invalid nr of permissions in list. round 2.")
	assert.Equal(t, 2, len(cache), "Invalid nr of cache items in list. round 2.")

	// Rectify missing group
	setup1_AddRoleGroup(t, c)
	cache = map[GroupIDU32]string{}
	idu32s2 := make([]GroupIDU32, 1)
	idu32s2[0] = GroupIDU32(3)

	// re-use the existing local cache
	plist, e = GroupIDsToNames(idu32s2, c.roleGroupDB, cache)
	fmt.Printf("Permissions: %v\n", plist)
	assert.Equal(t, 1, len(plist), "Invalid nr of permissions in list, round 3.")
	assert.Equal(t, 3, len(cache), "Invalid nr of cache items in list, round 3.")
}
