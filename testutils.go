package authaus

import (
	"io/ioutil"
	"log"
)

func NewCentralDummy(logger *log.Logger) *Central {
	authenticator := newDummyAuthenticator()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	roleGroupDB := newDummyRoleGroupDB()
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	central := NewCentral(logger, authenticator, permitDB, sessionDB, roleGroupDB)
	return central
}
