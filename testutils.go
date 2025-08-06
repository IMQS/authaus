package authaus

func NewCentralDummy(logfile string) *Central {
	userStore := newDummyUserStore()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	roleGroupDB := newDummyRoleGroupDB()
	usageTracker := NewCheckUsageTracker(ConfigUsageTracking{
		Enabled:       false,
		FlushInterval: 10,
	}, nil, nil)
	central := NewCentral(logfile, nil, nil, userStore, permitDB, sessionDB, roleGroupDB, usageTracker)

	return central
}
