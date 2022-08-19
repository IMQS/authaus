package authaus

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

// We try to keep most of the Role stuff inside this file, as a reminder that the
// role database is a completely optional component.

var (
	ErrGroupNotExist      = errors.New("Group does not exist")
	ErrGroupExists        = errors.New("Group already exists")
	ErrGroupNameIllegal   = errors.New("Group name may not be empty, and must not have spaces on the left or right")
	ErrGroupDuplicateName = errors.New("A group with that name already exists")
	ErrPermitInvalid      = errors.New("Permit is not a sequence of 32-bit words")
)

// Any permission in the system is uniquely described by a 16-bit unsigned integer
type PermissionU16 uint16

// A list of permissions
type PermissionList []PermissionU16

func (a *PermissionList) Diff(b *PermissionList) *PermissionList {
	d := PermissionList{}
	for _, ep := range *a {
		found := false
		for _, np := range *b {
			if ep == np {
				found = true
				break
			}
		}
		if !found {
			d = append(d, ep)
		}
	}
	return &d
}

// Has returns true if the list contains this permission
func (x PermissionList) Has(perm PermissionU16) bool {
	for _, bit := range x {
		if bit == perm {
			return true
		}
	}
	return false
}

// Add adds this permission to the list.
// Takes no action if the permission is already present.
func (x *PermissionList) Add(perm PermissionU16) {
	for _, bit := range *x {
		if bit == perm {
			return
		}
	}
	*x = append(*x, perm)
}

// Remove removes this permission from the lst
// Takes no action if the permission is not present.
func (x *PermissionList) Remove(perm PermissionU16) {
	for index, bit := range *x {
		if bit == perm {
			*x = append((*x)[0:index], (*x)[index+1:]...)
			return
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// A mapping from 16-bit permission number to a textual name of that permission
type PermissionNameTable map[PermissionU16]string

// Produces a map from permission name to permission number
func (x *PermissionNameTable) Inverted() map[string]PermissionU16 {
	inverted := map[string]PermissionU16{}
	for p, n := range *x {
		inverted[n] = p
	}
	return inverted
}

// GroupNameIsLegal asserts whether or not the name is legal
func GroupNameIsLegal(name string) bool {
	return name != "" && strings.TrimSpace(name) == name
}

// GroupIDU32 is our group IDs are unsigned 32-bit integers
type GroupIDU32 uint32

// GroupIDU32s is a containing the group IDs
type GroupIDU32s []GroupIDU32

// IndexOf returns the index of the group
func (gid *GroupIDU32s) IndexOf(idx GroupIDU32) int {
	for i, x := range *gid {
		if x == idx {
			return i
		}
	}
	return -1
}

// ContainsIndex returns whether or not the requested index is contained in the
// group
func (gid *GroupIDU32s) ContainsIndex(idx GroupIDU32) bool {
	return gid.IndexOf(idx) != -1
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// A Role Group database stores a list of Groups. Each Group has a list
// of permissions that it enables.
type RoleGroupDB interface {
	GetGroups() ([]*AuthGroup, error)
	GetGroupsRaw() ([]RawAuthGroup, error)
	GetByName(name string) (*AuthGroup, error)
	GetByID(id GroupIDU32) (*AuthGroup, error)
	InsertGroup(group *AuthGroup) error
	DeleteGroup(group *AuthGroup) error
	UpdateGroup(group *AuthGroup) error
	Close()
}

func LoadOrCreateGroup(roleDB RoleGroupDB, groupName string, createIfNotExist bool) (*AuthGroup, error) {
	if existing, eget := roleDB.GetByName(groupName); eget == nil {
		return existing, nil
	} else if strings.Index(eget.Error(), ErrGroupNotExist.Error()) == 0 {
		if createIfNotExist {
			group := &AuthGroup{}
			group.Name = groupName
			if ecreate := roleDB.InsertGroup(group); ecreate == nil {
				return group, nil
			} else {
				return nil, ecreate
			}
		} else {
			return nil, eget
		}
	} else {
		return nil, eget
	}
}

func DeleteGroup(roleDB RoleGroupDB, groupName string) error {
	group, eget := roleDB.GetByName(groupName)
	if eget != nil {
		return eget
	}
	return roleDB.DeleteGroup(group)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// An Authorization Group. This stores a list of permissions.
type AuthGroup struct {
	ID       GroupIDU32     // DB-generated id
	Name     string         // Administrators need this name to keep sense of things. Example of this is "finance" or "engineering".
	PermList PermissionList // Application-defined permission bits (ie every value from 0..65535 pertains to one particular permission)
}

type RawAuthGroup struct {
	ID       GroupIDU32
	Name     string
	PermList string
}

func (x *AuthGroup) encodePermList() string {
	return base64.StdEncoding.EncodeToString(encodePermList(x.PermList))
}

func (x AuthGroup) Clone() *AuthGroup {
	clone := &AuthGroup{}
	*clone = x
	clone.PermList = make(PermissionList, len(x.PermList))
	copy(clone.PermList, x.PermList)
	return clone
}

// This is a no-op if the permission is already set
func (x *AuthGroup) AddPerm(perm PermissionU16) {
	x.PermList.Add(perm)
}

// This is a no-op if the permission is not set
func (x *AuthGroup) RemovePerm(perm PermissionU16) {
	x.PermList.Remove(perm)
}

func (x *AuthGroup) HasPerm(perm PermissionU16) bool {
	return x.PermList.Has(perm)
}

// Encodes a list of Group IDs into a Permit
func EncodePermit(groupIds []GroupIDU32) []byte {
	res := make([]byte, len(groupIds)*4)
	for i := 0; i < len(groupIds); i++ {
		res[i*4] = byte((groupIds[i] >> 24) & 0xff)
		res[i*4+1] = byte((groupIds[i] >> 16) & 0xff)
		res[i*4+2] = byte((groupIds[i] >> 8) & 0xff)
		res[i*4+3] = byte(groupIds[i] & 0xff)
	}
	return res
}

// DecodePermit decodes a Permit into a list of Group IDs
func DecodePermit(permit []byte) (GroupIDU32s, error) {
	if len(permit)%4 != 0 {
		return nil, ErrPermitInvalid
	}
	groups := make([]GroupIDU32, len(permit)/4)
	for i := 0; i < len(permit); i += 4 {
		groups[i>>2] = 0 |
			GroupIDU32(permit[i])<<24 |
			GroupIDU32(permit[i+1])<<16 |
			GroupIDU32(permit[i+2])<<8 |
			GroupIDU32(permit[i+3])
		//fmt.Printf("Groups[%v] = %v\n", i>>2, groups[i>>2])
	}
	return groups, nil
}

type sqlGroupDB struct {
	db *sql.DB
}

// This goes from Permit -> Groups -> PermList
// Permit has 0..n Groups
// Group has 0..n PermList
// We produce a list of all unique PermList that appear in any
// of the groups inside this permit. You can think of this as a binary OR operation.
// In case of missing groups, the function will proceed with "best effort", but also set the error.
// Only the first error will be returned.
func PermitResolveToList(permit []byte, db RoleGroupDB) (PermissionList, error) {
	bits := make(map[PermissionU16]bool)
	var groupError error
	if groupIDs, err := DecodePermit(permit); err == nil {
		for _, gid := range groupIDs {
			if group, egroup := db.GetByID(gid); egroup != nil {
				if groupError == nil {
					groupError = egroup
				}
			} else {
				for _, bit := range group.PermList {
					bits[bit] = true
				}
			}
		}
		list := make(PermissionList, 0)
		for bit := range bits {
			list = append(list, bit)
		}
		return list, groupError
	} else {
		return nil, err
	}
}

// Converts group names to group IDs.
// From here you can use EncodePermit to get a blob that is ready for use
// as Permit.Roles
func GroupNamesToIDs(groups []string, db RoleGroupDB) ([]GroupIDU32, error) {
	ids := make([]GroupIDU32, len(groups))
	for i, gname := range groups {
		if group, err := db.GetByName(gname); err != nil {
			return nil, err
		} else {
			ids[i] = group.ID
		}
	}
	return ids, nil
}

func ReadRawGroups(importedGroups []RawAuthGroup) ([]AuthGroup, error) {
	var groups []AuthGroup
	for _, importedGroup := range importedGroups {
		if permList, epermit := parsePermListBase64(importedGroup.PermList); epermit == nil {
			groups = append(groups, AuthGroup{importedGroup.ID, importedGroup.Name, permList})
		} else {
			return nil, epermit
		}
	}
	return groups, nil
}

// GroupIDsToNames converts group IDs to names.
// The 'cache' parameter is used to speed up subsequent calls to this function, because this function tends to get used
// in loops. The function does not remove items from the cache - cache management is left to the consumer. Do not reuse
// the cache outside local iterative control structures or in longer running processes.
// In case of missing groups, the function will proceed with "best effort", but also set the error.
// Only the first error will be returned.
// On error, should the calling function decide to proceed, a null check MUST be performed on the `name` array.
func GroupIDsToNames(groupIds []GroupIDU32, db RoleGroupDB, cache map[GroupIDU32]string) (name []string, e error) {
	names := make([]string, 0, len(groupIds))
	var errGroup error
	if len(cache) == 0 {
		if err := addAllGroupNamesToCache(db, cache); err != nil {
			return nil, err
		}
	}

	for _, gid := range groupIds {
		if cache[gid] == "" {
			if errGroup == nil {
				errGroup = fmt.Errorf("Group %v not found", gid)
			}
		} else {
			names = append(names, cache[gid])
		}
	}

	return names, errGroup
}

func addAllGroupNamesToCache(db RoleGroupDB, cache map[GroupIDU32]string) error {
	if groupsDB, err := db.GetGroups(); err == nil {
		for _, giddb := range groupsDB {
			cache[giddb.ID] = giddb.Name
		}
	} else {
		return err
	}
	return nil
}

func encodePermList(permlist PermissionList) []byte {
	res := make([]byte, len(permlist)*2)
	for i := 0; i < len(permlist); i++ {
		res[i*2] = byte(permlist[i] >> 8)
		res[i*2+1] = byte(permlist[i])
	}
	return res
}

func parsePermListBase64(bitsB64 string) (PermissionList, error) {
	if bytes, errB64 := base64.StdEncoding.DecodeString(bitsB64); errB64 == nil {
		permList := make(PermissionList, 0)
		if len(bytes)%2 != 0 {
			return nil, errors.New("len(authgroup.permlist) mod 2 != 0")
		}
		for i := 0; i < len(bytes); i += 2 {
			permList = append(permList, PermissionU16(bytes[i])<<8|PermissionU16(bytes[i+1]))
		}
		return permList, nil
	} else {
		return nil, errB64
	}
}

func readSingleGroup(row *sql.Row, errDetail string) (*AuthGroup, error) {
	bitsB64 := ""
	group := &AuthGroup{}
	if err := row.Scan(&group.ID, &group.Name, &bitsB64); err == nil {
		var errB64 error
		if group.PermList, errB64 = parsePermListBase64(bitsB64); errB64 == nil {
			return group, nil
		} else {
			return nil, errB64
		}
	} else {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrGroupNotExist.Error() + ": " + errDetail)
		}
		return nil, err
	}
}

func readAllGroups(rows *sql.Rows, queryError error) ([]*AuthGroup, error) {
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	groups := make([]*AuthGroup, 0)
	for rows.Next() {
		bitsB64 := ""
		group := &AuthGroup{}
		if errScan := rows.Scan(&group.ID, &group.Name, &bitsB64); errScan == nil {
			var errB64 error
			if group.PermList, errB64 = parsePermListBase64(bitsB64); errB64 == nil {
				groups = append(groups, group)
			} else {
				return nil, errB64
			}
		} else {
			return nil, errScan
		}
	}
	return groups, nil
}

func (x *sqlGroupDB) GetGroups() ([]*AuthGroup, error) {
	return readAllGroups(x.db.Query("SELECT id,name,permlist FROM authgroup"))
}

func (x *sqlGroupDB) GetGroupsRaw() ([]RawAuthGroup, error) {
	rows, queryError := x.db.Query("SELECT id,name,permlist FROM authgroup")
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()

	var groups []RawAuthGroup
	for rows.Next() {
		r := RawAuthGroup{}
		if errScan := rows.Scan(&r.ID, &r.Name, &r.PermList); errScan != nil {
			return nil, errScan
		}
		groups = append(groups, r)
	}
	return groups, nil
}

func (x *sqlGroupDB) GetByName(name string) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", name)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permlist FROM authgroup WHERE name = $1", name), name)
}

func (x *sqlGroupDB) GetByID(id GroupIDU32) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", id)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permlist FROM authgroup WHERE id = $1", id), fmt.Sprintf("%v", id))
}

// InsertGroup adds a new group. If the function is successful, then 'group.ID' will be set to the inserted record's ID
func (x *sqlGroupDB) InsertGroup(group *AuthGroup) error {
	if !GroupNameIsLegal(group.Name) {
		return ErrGroupNameIllegal
	}
	row := x.db.QueryRow("INSERT INTO authgroup (name, permlist) VALUES ($1, $2) RETURNING id", group.Name, group.encodePermList())
	var lastId GroupIDU32
	if err := row.Scan(&lastId); err == nil {
		group.ID = lastId
		return nil
	} else {
		return err
	}
}

// Delete an existing group
func (x *sqlGroupDB) DeleteGroup(group *AuthGroup) error {
	if existingByName, _ := x.GetByName(group.Name); existingByName == nil {
		return ErrGroupNotExist
	}
	if _, err := x.db.Exec("DELETE FROM authgroup WHERE id=$1", group.ID); err == nil {
		return nil
	} else {
		return err
	}
}

// Update an existing group (by ID)
func (x *sqlGroupDB) UpdateGroup(group *AuthGroup) error {
	if group.ID == 0 {
		return ErrGroupNotExist
	}
	if !GroupNameIsLegal(group.Name) {
		return ErrGroupNameIllegal
	}
	if existingByName, _ := x.GetByName(group.Name); existingByName != nil && existingByName.ID != group.ID {
		return ErrGroupDuplicateName
	}
	if _, err := x.db.Exec("UPDATE authgroup SET name=$1, permlist=$2 WHERE id=$3", group.Name, group.encodePermList(), group.ID); err == nil {
		return nil
	} else {
		return err
	}
}

func (x *sqlGroupDB) Close() {
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
	Role Group cache

This caches all role groups from the backend database. We assume that this database will never be
particularly large, so we simply allow our cache to grow indefinitely.
All public functions are thread-safe.
*/
type RoleGroupCache struct {
	backend      RoleGroupDB
	groupsByID   map[GroupIDU32]*AuthGroup
	groupsByName map[string]*AuthGroup
	groupsLock   sync.RWMutex // this guards groupsByID, groupsByName, hasAll
	hasAll       bool
}

// GetGroupsRaw's results are not cached. The point is to get the current state of the db for the export
func (x *RoleGroupCache) GetGroupsRaw() ([]RawAuthGroup, error) {
	return x.backend.GetGroupsRaw()
}

func (x *RoleGroupCache) GetGroups() ([]*AuthGroup, error) {
	x.groupsLock.RLock()
	if x.hasAll {
		groups := make([]*AuthGroup, 0)
		for _, v := range x.groupsByName {
			groups = append(groups, v.Clone())
		}
		x.groupsLock.RUnlock()
		return groups, nil
	} else {
		// Fetch all groups from backend. This code looks racy: While we're fetching
		// the list of all groups, another thread could be inserting new groups. However,
		// this is OK, since those other inserted groups will be added to our cache
		// already. All we're doing here is filling in the blanks that existed before
		// this system came online.
		x.groupsLock.RUnlock()
		groups, err := x.backend.GetGroups()
		if err != nil {
			return nil, err
		}
		x.groupsLock.Lock()
		for _, group := range groups {
			x.insertInCache(group)
		}
		x.hasAll = true
		x.groupsLock.Unlock()
		return groups, nil
	}
}

func (x *RoleGroupCache) GetByName(name string) (*AuthGroup, error) {
	return x.get(true, name)
}

func (x *RoleGroupCache) GetByID(id GroupIDU32) (*AuthGroup, error) {
	return x.get(false, id)
}

func (x *RoleGroupCache) InsertGroup(group *AuthGroup) (err error) {
	// We need to hold the lock around the entire operation. If you try to "optimize" the lock
	// window by locking only the insertion into our cache, and not into the DB, then you introduce
	// the possibility of a discrepancy arising between the DB and the cache.
	// Since groups are modified seldom, this should not be a performance concern - at least
	// not for the envisaged use cases.
	x.groupsLock.Lock()
	if err = x.backend.InsertGroup(group); err == nil {
		x.insertInCache(group)
	}
	x.groupsLock.Unlock()
	return
}

func (x *RoleGroupCache) DeleteGroup(group *AuthGroup) (err error) {
	x.groupsLock.Lock()
	if err = x.backend.DeleteGroup(group); err == nil {
		x.removeFromCache(group)
	}
	x.groupsLock.Unlock()
	return
}

func (x *RoleGroupCache) UpdateGroup(group *AuthGroup) (err error) {
	oldGroup, _ := x.GetByID(group.ID)
	// Same comment here about locking, as in InsertGroup
	x.groupsLock.Lock()
	// Remove the old group from the cache to prevent duplicates
	if oldGroup.Name != group.Name {
		x.removeFromCache(oldGroup)
	}
	if err = x.backend.UpdateGroup(group); err == nil {
		x.insertInCache(group)
	}
	x.groupsLock.Unlock()
	return
}

func (x *RoleGroupCache) Close() {
	x.reset()
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

func (x *RoleGroupCache) get(byname bool, value interface{}) (group *AuthGroup, err error) {
	// Acquire from the cache
	x.groupsLock.RLock()
	if byname {
		group, _ = x.groupsByName[value.(string)]
	} else {
		group, _ = x.groupsByID[value.(GroupIDU32)]
	}
	x.groupsLock.RUnlock()
	if group != nil {
		return
	}

	// Acquire from the backend
	x.groupsLock.Lock()
	group, err = x.getFromBackend(byname, value)
	x.groupsLock.Unlock()
	return
}

// This function is exposed for testing
func (x *RoleGroupCache) lockAndReset() {
	x.groupsLock.Lock()
	x.reset()
	x.groupsLock.Unlock()
}

func (x *RoleGroupCache) reset() {
	x.groupsByID = make(map[GroupIDU32]*AuthGroup)
	x.groupsByName = make(map[string]*AuthGroup)
	x.hasAll = false
}

// Assume that groupsLock.WRITE is held
func (x *RoleGroupCache) getFromBackend(byname bool, value interface{}) (*AuthGroup, error) {
	var group *AuthGroup
	var err error
	if byname {
		group, err = x.backend.GetByName(value.(string))
	} else {
		group, err = x.backend.GetByID(value.(GroupIDU32))
	}

	if err == nil {
		x.insertInCache(group)
		return group, nil
	} else {
		return nil, err
	}
}

// Assume that groupsLock.WRITE is held
func (x *RoleGroupCache) insertInCache(group *AuthGroup) {
	gcopy := group.Clone()
	x.groupsByID[group.ID] = gcopy
	x.groupsByName[group.Name] = gcopy
}

func (x *RoleGroupCache) removeFromCache(group *AuthGroup) {
	delete(x.groupsByID, group.ID)
	delete(x.groupsByName, group.Name)
}

// Create a new RoleGroupDB that transparently caches reads of groups
func NewCachedRoleGroupDB(backend RoleGroupDB) RoleGroupDB {
	cached := &RoleGroupCache{}
	cached.reset()
	cached.backend = backend
	return cached
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewRoleGroupDB_SQL(db *sql.DB) (RoleGroupDB, error) {
	roles := &sqlGroupDB{}
	roles.db = db
	return roles, nil
}

//// Create a Postgres DB schema necessary for our Groups database
//func SqlCreateSchema_RoleGroupDB(conx *DBConnection) error {
//	versions := make([]string, 0)
//	versions = append(versions, `
//	CREATE TABLE authgroup (id SERIAL PRIMARY KEY, name VARCHAR, permlist VARCHAR);
//	CREATE UNIQUE INDEX idx_authgroup_name ON authgroup (name);`)
//
//	return MigrateSchema(conx, "authgroup", versions)
//}
