package authaus

import "sync"

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

func (x *dummyRoleGroupDB) GetGroups() ([]*AuthGroup, error) {
	groups := []*AuthGroup{}
	x.groupsLock.RLock()
	for _, v := range x.groupsByName {
		groups = append(groups, v.Clone())
	}
	x.groupsLock.RUnlock()
	return groups, nil
}

func (x *dummyRoleGroupDB) GetGroupsRaw() ([]RawAuthGroup, error) {
	return nil, nil
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

func (x *dummyRoleGroupDB) DeleteGroup(group *AuthGroup) error {
	x.groupsLock.Lock()
	defer x.groupsLock.Unlock()
	if existingByName := x.groupsByName[group.Name]; existingByName == nil {
		return ErrGroupNotExist
	}
	delete(x.groupsByID, group.ID)
	delete(x.groupsByName, group.Name)
	return nil
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
