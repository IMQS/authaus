package authaus

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"strings"
	"sync"
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

// Returns true if the permission list contains this permission
func (x PermissionList) Has(perm PermissionU16) bool {
	for _, bit := range x {
		if bit == perm {
			return true
		}
	}
	return false
}

// A mapping from 16-bit permission number to a textual description of that permission
type PermissionNameTable []string

func (x PermissionNameTable) Get(perm PermissionU16) string {
	return x[perm]
}

func (x *PermissionNameTable) Append(perm PermissionU16, description string) {
	if len(*x) != int(perm) {
		// This is just a sanity check. Why would you want to do it any other way?
		panic("You must build up a permission table from empty, without any gaps in the enumerations")
	}
	*x = append(*x, description)
}

func GroupNameIsLegal(name string) bool {
	return name != "" && strings.TrimSpace(name) == name
}

// Our group IDs are unsigned 32-bit integers
type GroupIDU32 uint32

// A Role Group database stores a list of Groups. Each Group has a list
// of permissions that it enables.
type RoleGroupDB interface {
	GetByName(name string) (*AuthGroup, error)
	GetByID(id GroupIDU32) (*AuthGroup, error)
	InsertGroup(group *AuthGroup) error
	UpdateGroup(group *AuthGroup) error
	Close()
}

// An Authorization Group. This stores a list of permissions.
type AuthGroup struct {
	ID       GroupIDU32     // DB-generated id
	Name     string         // Administrators need this name to keep sense of things. Example of this is "finance" or "engineering".
	PermList PermissionList // Application-defined permission bits (ie every value from 0..65535 pertains to one particular permission)
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

// This is a no-op if the bit is already set
func (x *AuthGroup) AddPermBit(permBit PermissionU16) {
	for _, bit := range x.PermList {
		if bit == permBit {
			return
		}
	}
	x.PermList = append(x.PermList, permBit)
}

// This is a no-op if the bit is not set
func (x *AuthGroup) RemovePermBit(permBit PermissionU16) {
	for index, bit := range x.PermList {
		if bit == permBit {
			x.PermList = append(x.PermList[0:index], x.PermList[index+1:]...)
			return
		}
	}
}

func (x *AuthGroup) HasBit(permBit PermissionU16) bool {
	for _, bit := range x.PermList {
		if bit == permBit {
			return true
		}
	}
	return false
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

// Decodes a Permit into a list of Group IDs
func DecodePermit(permit []byte) ([]GroupIDU32, error) {
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type dummyRoleGroupDB struct {
	groupsByName map[string]*AuthGroup
	groupsByID   map[GroupIDU32]*AuthGroup
	groupsLock   sync.RWMutex
	groupsNextID GroupIDU32
}

func newDummyRoleGroupDB() *dummyRoleGroupDB {
	db := &dummyRoleGroupDB{}
	db.groupsByName = make(map[string]*AuthGroup)
	db.groupsByID = make(map[GroupIDU32]*AuthGroup)
	db.groupsNextID = 1
	return db
}

func (x *dummyRoleGroupDB) GetByName(name string) (*AuthGroup, error) {
	x.groupsLock.RLock()
	defer x.groupsLock.RUnlock()
	g := x.groupsByName[name]
	if g != nil {
		return g, nil
	} else {
		return nil, ErrGroupNotExist
	}
}

func (x *dummyRoleGroupDB) GetByID(id GroupIDU32) (*AuthGroup, error) {
	x.groupsLock.RLock()
	defer x.groupsLock.RUnlock()
	g := x.groupsByID[id]
	if g != nil {
		return g, nil
	} else {
		return nil, ErrGroupNotExist
	}
}

func (x *dummyRoleGroupDB) InsertGroup(group *AuthGroup) error {
	if !GroupNameIsLegal(group.Name) {
		return ErrGroupNameIllegal
	}
	x.groupsLock.Lock()
	defer x.groupsLock.Unlock()
	if x.groupsByName[group.Name] != nil {
		return ErrGroupExists
	} else {
		group.ID = x.groupsNextID
		x.groupsByID[group.ID] = group
		x.groupsByName[group.Name] = group
		x.groupsNextID += 1
		return nil
	}
}

func (x *dummyRoleGroupDB) UpdateGroup(group *AuthGroup) error {
	x.groupsLock.Lock()
	defer x.groupsLock.Unlock()
	if !GroupNameIsLegal(group.Name) {
		return ErrGroupNameIllegal
	}
	if existingByName := x.groupsByName[group.Name]; existingByName != nil && existingByName.ID != group.ID {
		return ErrGroupDuplicateName
	}

	if existingByID := x.groupsByID[group.ID]; existingByID == nil {
		return ErrGroupNotExist
	} else {
		delete(x.groupsByName, existingByID.Name)
		clone := group.Clone()
		x.groupsByName[group.Name] = clone
		x.groupsByID[group.ID] = clone
		return nil
	}
}

func (x *dummyRoleGroupDB) Close() {
	x.groupsByID = nil
	x.groupsByName = nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlGroupDB struct {
	db *sql.DB
}

// This goes from Permit -> Groups -> PermList
// Permit has 0..n Groups
// Group has 0..n PermList
// We produce a list of all unique PermList that appear in any
// of the groups inside this permit. You can think of this as a binary OR operation.
func PermitResolveToList(permit []byte, db RoleGroupDB) (PermissionList, error) {
	bits := make(map[PermissionU16]bool, 0)
	if groupIDs, err := DecodePermit(permit); err == nil {
		for _, gid := range groupIDs {
			if group, egroup := db.GetByID(gid); egroup != nil {
				return nil, egroup
			} else {
				for _, bit := range group.PermList {
					bits[bit] = true
				}
			}
		}
		list := make(PermissionList, 0)
		for bit, _ := range bits {
			list = append(list, bit)
		}
		return list, nil
	} else {
		return nil, err
	}
	// unreachable
	return nil, nil
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

// Converts group IDs to names
func GroupIDsToNames(groups []GroupIDU32, db RoleGroupDB) ([]string, error) {
	names := make([]string, len(groups))
	for i, gid := range groups {
		if group, err := db.GetByID(gid); err != nil {
			return nil, err
		} else {
			names[i] = group.Name
		}
	}
	return names, nil
}

func encodePermList(permlist PermissionList) []byte {
	res := make([]byte, len(permlist)*2)
	for i := 0; i < len(permlist); i++ {
		res[i*2] = byte(permlist[i] >> 8)
		res[i*2+1] = byte(permlist[i])
	}
	return res
}

func readSingleGroup(row *sql.Row, errDetail string) (*AuthGroup, error) {
	group := &AuthGroup{}
	bitsb64 := ""
	if err := row.Scan(&group.ID, &group.Name, &bitsb64); err == nil {
		if bytes, e64 := base64.StdEncoding.DecodeString(bitsb64); e64 == nil {
			if len(bytes)%2 != 0 {
				return nil, errors.New("len(authgroup.permlist) mod 2 != 0")
			}
			for i := 0; i < len(bytes); i += 2 {
				group.PermList = append(group.PermList, PermissionU16(bytes[i])<<8|PermissionU16(bytes[i+1]))
			}
			return group, nil
		} else {
			return nil, e64
		}
	} else {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrGroupNotExist.Error() + ": " + errDetail)
		}
		return nil, err
	}
	// unreachable
	return nil, nil
}

func (x *sqlGroupDB) GetByName(name string) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", name)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permlist FROM authgroup WHERE name = $1", name), name)
}

func (x *sqlGroupDB) GetByID(id GroupIDU32) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", id)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permlist FROM authgroup WHERE id = $1", id), fmt.Sprintf("%v", id))
}

// Add a new group. If the function is successful, then 'group.ID' will be set to the inserted record's ID
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
	// unreachable
	return nil
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
	// unreachable
	return nil
}

func (x *sqlGroupDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Role Group cache
This caches all role groups from the backend database. We assume that this database will never be
particularly large, so we simply allow our cache to grow indefinitely.
All public functions are thread-safe.
*/
type RoleGroupCache struct {
	backend      RoleGroupDB
	groupsByID   map[GroupIDU32]*AuthGroup
	groupsByName map[string]*AuthGroup
	groupsLock   sync.RWMutex
}

func (x *RoleGroupCache) GetByName(name string) (*AuthGroup, error) {
	return x.get(true, name)
}

func (x *RoleGroupCache) GetByID(id GroupIDU32) (*AuthGroup, error) {
	return x.get(false, id)
}

func (x *RoleGroupCache) InsertGroup(group *AuthGroup) error {
	if err := x.backend.InsertGroup(group); err == nil {
		x.groupsLock.Lock()
		x.insertInCache(*group)
		x.groupsLock.Unlock()
		return nil
	} else {
		return err
	}
	// unreachable
	return nil
}

func (x *RoleGroupCache) UpdateGroup(group *AuthGroup) error {
	if err := x.backend.UpdateGroup(group); err == nil {
		x.groupsLock.Lock()
		x.insertInCache(*group)
		x.groupsLock.Unlock()
		return nil
	} else {
		return err
	}
	// unreachable
	return nil
}

func (x *RoleGroupCache) Close() {
	x.resetMaps()
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

func (x *RoleGroupCache) get(byname bool, value interface{}) (*AuthGroup, error) {
	// Acquire from the cache
	x.groupsLock.RLock()
	var group *AuthGroup
	if byname {
		group, _ = x.groupsByName[value.(string)]
	} else {
		group, _ = x.groupsByID[value.(GroupIDU32)]
	}
	x.groupsLock.RUnlock()
	if group != nil {
		return group, nil
	}

	// Acquire from the backend
	x.groupsLock.Lock()
	var err error
	group, err = x.getFromBackend(byname, value)
	x.groupsLock.Unlock()
	return group, err
}

func (x *RoleGroupCache) resetMaps() {
	x.groupsByID = make(map[GroupIDU32]*AuthGroup)
	x.groupsByName = make(map[string]*AuthGroup)
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
		x.insertInCache(*group)
		return group, nil
	} else {
		return nil, err
	}

	// unreachable
	return nil, nil
}

// Assume that groupsLock.WRITE is held
func (x *RoleGroupCache) insertInCache(group AuthGroup) {
	gcopy := group.Clone()
	x.groupsByID[group.ID] = gcopy
	x.groupsByName[group.Name] = gcopy
}

// Create a new RoleGroupDB that transparently caches reads of groups
func NewCachedRoleGroupDB(backend RoleGroupDB) RoleGroupDB {
	cached := &RoleGroupCache{}
	cached.resetMaps()
	cached.backend = backend
	return cached
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewRoleGroupDB_SQL(conx *DBConnection) (RoleGroupDB, error) {
	var err error
	db := &sqlGroupDB{}
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

// Create a Postgres DB schema necessary for our Groups database
func SqlCreateSchema_RoleGroupDB(conx *DBConnection) error {
	versions := make([]string, 0)
	versions = append(versions, `
	CREATE TABLE authgroup (id SERIAL PRIMARY KEY, name VARCHAR, permlist VARCHAR);
	CREATE UNIQUE INDEX idx_authgroup_name ON authgroup (name);`)

	return MigrateSchema(conx, "authgroup", versions)
}
