package authaus

import (
	"bytes"
	"database/sql"
	"flag"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"
)

/*
NOTE: Some of these tests stress concurrency, so you must run them with at least -test.cpu 2

TODO: Add test that verifies that SetPassword does not create an identity if that identity does not already exist

Create a test Postgres database:
	create role authaus_test login password 'authaus_test';
	create database authaus_test owner = authaus_test;

Suggested test runs that you should do:

	go test github.com/IMQS/authaus -test.cpu 2
	go test github.com/IMQS/authaus -test.cpu 2 -backend_postgres
	go test -race github.com/IMQS/authaus -test.cpu 2
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_postgres

In other words, test with and without race detector, and with dummy backend,
and Postgres backend. I'm not sure that testing without the race detector adds any value.
*/

var backend_postgres = flag.Bool("backend_postgres", false, "Run tests against Postgres backend")

var conx_postgres = DBConnection{
	Driver:   "postgres",
	Host:     "localhost",
	Port:     5432,
	Database: "authaus_test",
	User:     "authaus_test",
	Password: "authaus_test",
	SSL:      false,
}

func isBackendTest() bool {
	return *backend_postgres
}

func setup1_joePermit() Permit {
	p := Permit{}
	r := [2]byte{1, 2}
	p.Roles = r[:]
	return p
}

func setup1(t *testing.T) *Central {
	var authenticator Authenticator
	var sessionDB SessionDB
	var permitDB PermitDB
	var roleDB RoleGroupDB

	connectToDB := func(conx DBConnection) {
		dbName := conx.Host + ":" + conx.Database

		if ecreate := SqlCreateDatabase(&conx); ecreate != nil {
			t.Fatalf("Unable to create test database: %v: %v", dbName, ecreate)
		}

		if db, errdb := conx.Connect(); errdb != nil {
			t.Fatalf("Unable to connect to database %v: %v", dbName, errdb)
		} else {
			if err := sqlDeleteAllTables(db); err != nil {
				t.Fatalf("Unable to wipe database %v: %v", dbName, err)
			}
			if err := SqlCreateSchema_Session(&conx); err != nil {
				t.Fatalf("Unable to create session schema in database %v: %v", dbName, err)
			}
			if err := SqlCreateSchema_User(&conx); err != nil {
				t.Fatalf("Unable to create user schema in database %v: %v", dbName, err)
			}
			if err := SqlCreateSchema_RoleGroupDB(&conx); err != nil {
				t.Fatalf("Unable to create role/group schema in database %v: %v", dbName, err)
			}
		}

		var err [4]error
		authenticator, err[0] = NewAuthenticationDB_SQL(&conx)
		sessionDB, err[1] = NewSessionDB_SQL(&conx)
		permitDB, err[2] = NewPermitDB_SQL(&conx)
		roleDB, err[3] = NewRoleGroupDB_SQL(&conx)
		if firstError(err[:]) != nil {
			t.Fatalf("Unable to connect to database %v: %v", dbName, firstError(err[:]))
		}
	}

	if *backend_postgres {
		connectToDB(conx_postgres)
	} else {
		authenticator = newDummyAuthenticator()
		sessionDB = newDummySessionDB()
		permitDB = newDummyPermitDB()
		roleDB = newDummyRoleGroupDB()
	}
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	central := NewCentral(logger, authenticator, permitDB, sessionDB, roleDB)

	joePermit := setup1_joePermit()
	if e := authenticator.CreateIdentity("joe", "123"); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	if e := authenticator.CreateIdentity("jack", "12345"); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	if e := authenticator.CreateIdentity("iHaveNoPermit", "123"); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	permitDB.SetPermit("joe", &joePermit)

	return central
}

func firstError(errors []error) error {
	for _, e := range errors {
		if e != nil {
			return e
		}
	}
	return nil
}

func sqlDeleteAllTables(db *sql.DB) error {
	statements := []string{
		"DROP TABLE IF EXISTS authgroup",
		"DROP TABLE IF EXISTS authsession",
		"DROP TABLE IF EXISTS authuser",
		"DROP TABLE IF EXISTS authgroup_version",
		"DROP TABLE IF EXISTS authsession_version",
		"DROP TABLE IF EXISTS authuser_version",
	}
	for _, st := range statements {
		if _, err := db.Exec(st); err != nil {
			return err
		}
	}
	return nil
}

func isPrefix(prefix, str string) bool {
	return strings.Index(str, prefix) == 0
}

func TestIdentityCaseSensitivity(t *testing.T) {
	c := setup1(t)

	if e := c.CreateAuthenticatorIdentity("JOE", "123"); e == nil || !isPrefix(ErrIdentityExists.Error(), e.Error()) {
		t.Errorf("CreateIdentity should fail because identities are case-insensitive. Instead, error is %v", e)
	}
	perm := Permit{}
	roles := [2]byte{99}
	perm.Roles = roles[:]
	if e := c.SetPermit("JOE", &perm); e != nil {
		t.Errorf("SetPermit should ignore identity case")
	}

	if p1, e := c.GetPermit("joe"); e != nil || !p1.Equals(&perm) {
		t.Errorf("SetPermit or GetPermit is not ignoring case")
	}
	if p1, e := c.GetPermit("JOE"); e != nil || !p1.Equals(&perm) {
		t.Errorf("SetPermit or GetPermit is not ignoring case")
	}
}

func TestRenameIdentity(t *testing.T) {
	c := setup1(t)

	// Fail to rename 'joe', because 'jack' already exists
	if err := c.RenameIdentity("joe", "jack"); err != ErrIdentityExists {
		t.Fatalf("Rename should not have succeeded")
	}

	// Fail to rename 'foo', because 'foo' does not exist
	if err := c.RenameIdentity("foo", "boo"); err != ErrIdentityAuthNotFound {
		t.Fatalf("Rename should have failed with ErrIdentityAuthNotFound")
	}

	// Succeed renaming 'joe' to 'sarah'
	session, _, _ := c.Login("joe", "123")
	if _, err := c.GetTokenFromSession(session); err != nil {
		t.Fatalf("Expected good login")
	}

	if err := c.RenameIdentity("joe", "sarah"); err != nil {
		t.Fatalf("Rename should have succeeded, but error was %v", err)
	}

	if _, err := c.GetTokenFromSession(session); err != ErrInvalidSessionToken {
		t.Fatalf("All sessions for 'joe' should have been invalidated by rename")
	}

	if _, _, err := c.Login("sarah", "123"); err != nil {
		t.Fatalf("Login as 'sarah' failed (%v)", err)
	}
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
	expect_username_password("JOE", "123", "")
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
	if isBackendTest() {
		conPerThread = int64(100)
	}
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

func TestMaxSessionLimit(t *testing.T) {
	c := setup1(t)
	c.MaxActiveSessions = 1

	// Login first time
	key1, _, _ := c.Login("joe", "123")
	_, err := c.GetTokenFromSession(key1)
	if err != nil {
		t.Fatalf("Expected key1 to be valid")
	}

	// Login second time. After this, key1 must be invalid
	key2, _, _ := c.Login("joe", "123")
	_, err = c.GetTokenFromSession(key1)
	if err == nil {
		t.Fatalf("Expected key1 to be invalid")
	}
	_, err = c.GetTokenFromSession(key2)
	if err != nil {
		t.Fatalf("Expected key2 to be valid")
	}
}

func TestSessionCacheEviction(t *testing.T) {
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

func TestSessionDelete(t *testing.T) {
	c := setup1(t)
	key, _, _ := c.Login("joe", "123")
	_, err := c.GetTokenFromSession(key)
	if err != nil {
		t.Error("Login should not fail so early")
	}
	c.Logout(key)
	_, err = c.GetTokenFromSession(key)
	if err != ErrInvalidSessionToken {
		t.Error("Expected ErrInvalidSessionToken after Logout")
	}
}
