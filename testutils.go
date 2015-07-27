package authaus

func NewCentralDummy(logfile string) *Central {
	authenticator := newDummyAuthenticator()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	roleGroupDB := newDummyRoleGroupDB()
	central := NewCentral(logfile, authenticator, permitDB, sessionDB, roleGroupDB)
	return central
}
