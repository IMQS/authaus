package authaus

func NewCentralDummy(logfile string) *Central {
	userStore := newDummyUserStore()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	roleGroupDB := newDummyRoleGroupDB()
	central := NewCentral(logfile, nil, nil, userStore, permitDB, sessionDB, roleGroupDB)
	return central
}
