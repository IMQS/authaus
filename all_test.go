package authaus

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"
)

// NOTE: Some of these tests stress concurrency, so you must run them with at least -test.cpu 2

func setup1_joePermit() Permit {
	p := Permit{}
	r := [2]byte{1, 2}
	p.Roles = r[:]
	return p
}

func setup1(t *testing.T) *Central {
	authenticator := NewDummyAuthenticator()
	sessionDB := newDummySessionDB()
	permitDB := newDummyPermitDB()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	central := NewCentral(logger, authenticator, permitDB, sessionDB, nil)

	joePermit := setup1_joePermit()
	if e := authenticator.CreateIdentity("joe", "123"); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	if e := authenticator.CreateIdentity("iHaveNoPermit", "123"); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	permitDB.SetPermit("joe", &joePermit)

	return central
}

func TestBasicAuth(t *testing.T) {
	c := setup1(t)

	expect_username_password := func(username, password, expectErrorStart string) {
		token, err := c.GetTokenFromIdentityPassword(username, password)
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
	c := setup1(t)
	token, e := c.GetTokenFromIdentityPassword("joe", "123")
	if e != nil {
		t.Errorf("Unexpected error in TestPermit: %v", e)
	}
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
	c := setup1(t)

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
			token, err := c.GetTokenFromSession(sessionKeys[iter])
			if token == nil || err != nil {
				t.Errorf("GetTokenFromSession failed")
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

// This verifies that long-lived security tokens are updated correctly when their permits change
func TestPermitChange(t *testing.T) {
	c := setup1(t)
	perm1 := setup1_joePermit()
	perm2 := &Permit{}
	perm2_roles := [3]byte{5, 6, 7}
	perm2.Roles = perm2_roles[:]
	for nsessions := 1; nsessions < 100; nsessions *= 2 {
		// restore password and permit
		if e := c.SetPassword("joe", "123"); e != nil {
			t.Fatalf("Password restore failed: %v (nsessions = %v)", e, nsessions)
		}
		if e := c.SetPermit("joe", &perm1); e != nil {
			t.Fatalf("Permit restore failed: %v", e)
		}

		keys := make([]string, nsessions)
		tokens := make([]*Token, nsessions)
		for i := 0; i < nsessions; i++ {
			keys[i], tokens[i], _ = c.Login("joe", "123")
			if !bytes.Equal(tokens[i].Permit.Roles, perm1.Roles) {
				t.Fatalf("Permits not equal %v %v\n", tokens[i].Permit.Roles, perm1.Roles)
			}
		}
		// Set a new permit
		c.SetPermit("joe", perm2)
		for i := 0; i < nsessions; i++ {
			token, e := c.GetTokenFromSession(keys[i])
			if e != nil {
				t.Fatalf("Permit from session not found after permit change: %v\n", e)
			}
			if !bytes.Equal(token.Permit.Roles, perm2.Roles) {
				t.Fatalf("Permits not equal %v %v\n", token.Permit.Roles, perm2.Roles)
			}
		}
		// Change a password. This invalidates all sessions.
		c.SetPassword("joe", "456")
		for i := 0; i < nsessions; i++ {
			_, e := c.GetTokenFromSession(keys[i])
			if e == nil {
				t.Fatalf("Session not correctly invalidated after password change")
			}
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	c := setup1(t)
	c.NewSessionExpiresAfter = time.Millisecond * 500
	key, _, _ := c.Login("joe", "123")
	expire_time := time.Now().Add(c.NewSessionExpiresAfter)
	t.Logf("Expect failure at %v", expire_time)
	num_expire := 0
	for num_expire < 5 {
		expect_ok := time.Now().UnixNano() < expire_time.UnixNano()
		token, err := c.GetTokenFromSession(key)
		t.Logf("Expect: %v\n", expect_ok)
		if (token != nil) != expect_ok {
			t.Fatalf("Session timeout failed - unexpected token return value %v", token)
		}
		if (err == nil) != expect_ok {
			t.Fatalf("Session timeout failed - unexpected error return value %v", err)
		}
		if err != nil {
			num_expire += 1
		}
		// make sure this is relatively prime to our expiry time or you'll be subject to false-positive-inducing races
		time.Sleep(time.Millisecond * 300)
	}
}

func TestSessionCache(t *testing.T) {
	c := setup1(t)
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
				if _, e := c.GetTokenFromSession(ttok); e != nil {
					t.Errorf("Token should not have been evicted from cache %v:%v:%v", i, j, ttok)
					break
				}
			}
			c.debugEnableSessionDB(true)
			sessionList = expectList
		}
	}
}
