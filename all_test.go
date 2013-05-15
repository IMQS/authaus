package authaus

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"strings"
	"testing"
	"time"
)

func setup1() *Central {
	authenticator := NewDummyAuthenticator()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	central := NewCentral(authenticator, permitDB, sessionDB)

	joePermit := &Permit{}
	joePermit.Roles = append(joePermit.Roles, 1)
	joePermit.Roles = append(joePermit.Roles, 2)
	authenticator.SetPassword("joe", "123")
	authenticator.SetPassword("iHaveNoPermit", "123")
	permitDB.SetPermit("joe", joePermit)

	return central
}

func TestBasicAuth(t *testing.T) {
	c := setup1()

	expect_username_password := func(username, password, expectErrorStart string) {
		token, err := c.GetTokenForIdentityPassword(username, password)
		if (token == nil) != (err != nil) {
			t.Errorf("%v:%v -> (Token == nil) != (err != nil)", username, password)
		}
		if err != nil && strings.Index(err.Error(), expectErrorStart) != 0 {
			t.Errorf("%v:%v -> Expected '%v' prefix (but error starts with '%v')", username, password, expectErrorStart, err.Error())
		}
	}

	expect_username_password("123", "joe", ErrIdentityAuthNotFound.Error())
	expect_username_password("iHaveNoPermit", "123", ErrIdentityPermitNotFound.Error())
	expect_username_password("joe", "wrong", ErrInvalidPassword.Error())
	expect_username_password("joe", "", ErrInvalidPassword.Error())
	expect_username_password("joe", " ", ErrInvalidPassword.Error())
	expect_username_password("", "123", ErrIdentityEmpty.Error())
	expect_username_password(" ", "123", ErrIdentityEmpty.Error())
	expect_username_password("joe", "123", "")
}

func TestPermit(t *testing.T) {
	c := setup1()
	token, _ := c.GetTokenForIdentityPassword("joe", "123")
	if !bytes.Equal(token.Permit.Roles, []byte{1, 2}) {
		t.Errorf("joe Permit is wrong")
	}
}

func BenchmarkScrypt256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		scrypt.Key([]byte("a short password"), []byte("a short salt"), 256, 8, 1, 32)
	}
}

// This test must be run with at least 2 processors "go test -test.cpu 2"
func TestLoad(t *testing.T) {
	c := setup1()

	doLogin := func(myid int, times int64, ch chan<- bool) {
		sessionKeys := make([]string, times)
		for iter := int64(0); iter < times; iter++ {
			//t.Logf("%v: %v/%v login\n", myid, iter, times)
			key, token, err := c.Login("joe", "123")
			if err != nil {
				t.Errorf("Login failed. Error should not be %v", err)
			}
			if token == nil {
				t.Errorf("Login failed. Token should not be nil")
			}
			sessionKeys[iter] = key
		}
		for iter := int64(0); iter < times; iter++ {
			token, err := c.GetTokenForSession(sessionKeys[iter])
			if token == nil || err != nil {
				t.Errorf("GetTokenForSession failed")
			}
		}
		ch <- true
	}

	nsimul := 20
	conPerThread := int64(10000)
	waits := make([]chan bool, nsimul)
	for i := 0; i < nsimul; i++ {
		waits[i] = make(chan bool, 0)
		go doLogin(i, conPerThread, waits[i])
	}
	for i := 0; i < nsimul; i++ {
		_, ok := <-waits[i]
		if !ok {
			t.Errorf("Channel closed prematurely")
		}
	}
}

func TestSessionCache(t *testing.T) {
	c := setup1()
	login := func(username, password string) string {
		sessionkey, token, error := c.Login(username, password)
		if token == nil || error != nil {
			t.Errorf("Login failed '%v'", error)
		}
		return sessionkey
	}
	cacheSize := 100
	c.SetSessionCacheSize(cacheSize)
	sessionSet := make(map[string]bool)
	sessionList := make([]string, 0)
	for i := 0; i < cacheSize*4; i += 1 {
		// We must have time between sessions, so that the internal date ordering of the
		// session cache pruning function is the same as the order in which the sessions were added.
		time.Sleep(50 * time.Microsecond)
		sessionkey := login("joe", "123")
		if sessionSet[sessionkey] {
			t.Error("Same session key issued twice")
		}
		sessionSet[sessionkey] = true
		sessionList = append(sessionList, sessionkey)
		if i > cacheSize {
			// at any point from here onwards we expect at least cacheSize/2 entries in the cache
			c.debugEnableSessionDB(false)
			expectList := sessionList[len(sessionList)-cacheSize/2+1:]
			for j, ttok := range expectList {
				if _, e := c.GetTokenForSession(ttok); e != nil {
					t.Errorf("Token should not have been evicted from cache %v:%v:%v", i, j, ttok)
					break
				}
			}
			c.debugEnableSessionDB(true)
			sessionList = expectList
		}
	}
}
