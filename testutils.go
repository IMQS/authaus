package authaus

func NewCentralDummy(logfile string) *Central {
	userStoreAndAuth := newDummyUserStoreAndAuth()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	roleGroupDB := newDummyRoleGroupDB()
	central := NewCentral(logfile, userStoreAndAuth, userStoreAndAuth, permitDB, sessionDB, roleGroupDB)
	return central
}
