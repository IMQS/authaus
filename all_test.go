package authaus

import (
	"bytes"
	"database/sql"
	"flag"
	"github.com/IMQS/log"
	"golang.org/x/crypto/scrypt"
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

	---- Without race detector ---

	-- Test using maps/arrays mocking the backend:
	go test github.com/IMQS/authaus -test.cpu 2

	-- Test using postgres as the backend:
	go test github.com/IMQS/authaus -test.cpu 2 -backend_postgres

	-- Test using maps/arrays to mock ldap and the backend:
	go test github.com/IMQS/authaus -test.cpu 2 -backend_ldap

	-- Test using postgres as the backend and connecting to our LDAP system:
	*NOTE This test may only be run when on the IMQS domain, else it will fail
	go test github.com/IMQS/authaus -test.cpu 2 -backend_ldap -backend_postgres

	---- With race detector ----

	-- Test using maps/arrays mocking the backend:
	go test -race github.com/IMQS/authaus -test.cpu 2

	-- Test using postgres as the backend:
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_postgres

	-- Test using maps/arrays to mock ldap and the backend:
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_ldap

	-- Test using postgres as the backend and connecting to our LDAP system:
	*NOTE This test may only be run when on the IMQS domain, else it will fail
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_postgres -backend_ldap


I'm not sure that testing without the race detector adds any value.
*/

var backend_postgres = flag.Bool("backend_postgres", false, "Run tests against Postgres backend")
var backend_ldap = flag.Bool("backend_ldap", false, "Run tests against LDAP backend")

// These are hard-coded identities for unit test predictability
var joeIdentity = "joe"
var jackIdentity = "jack"
var SamIdentity = "Sam"
var iHaveNoPermitIdentity = "iHaveNoPermit"
var tomIdentity = "tomh"

// These are hard-coded passwords for unit test predictability
var joePwd = "1234abcd"
var jackPwd = "abcd1234"
var SamPwd = "12341234"
var iHaveNoPermitPwd = "1234wxyz"
var tomPwd = "12345678"

// These hard-coded UserId values are predictable because we always drop & recreate the postgres backend when running
// tests, so we know that our IDs always start at 1
var joeUserId UserId = 1
var jackUserId UserId = 2
var samUserId UserId = 3
var iHaveNoPermit UserId = 4
var tomUserId UserId = 5
var notFoundUserId UserId = 999
var ldapTest *dummyLdap

var conx_postgres = DBConnection{
	Driver:   "postgres",
	Host:     "localhost",
	Port:     5432,
	Database: "authaus_test",
	User:     "authaus_test",
	Password: "authaus_test",
	SSL:      false,
}

var conx_ldap = ConfigLDAP{
	Encryption:     "",
	LdapDomain:     "imqs.local",
	LdapHost:       "imqs.local",
	LdapPassword:   joePwd,
	LdapUsername:   (joeIdentity + "@imqs.local"),
	LdapPort:       389,
	LdapTickerTime: 5,
}

func isBackendTest() bool {
	return *backend_postgres
}

func setup1_permit() Permit {
	p := Permit{}
	r := [2]byte{1, 2}
	p.Roles = r[:]
	return p
}

func setup1(t *testing.T) *Central {
	var ldap LDAP
	var userStore UserStore
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

			if err := RunMigrations(&conx); err != nil {
				t.Fatalf("Unable to run migrations: %v", err)
			}
		}

		var err [4]error
		userStore, err[0] = NewUserStoreDB_SQL(&conx, *backend_ldap)
		sessionDB, err[1] = NewSessionDB_SQL(&conx)
		permitDB, err[2] = NewPermitDB_SQL(&conx)
		roleDB, err[3] = NewRoleGroupDB_SQL(&conx)
		if firstError(err[:]) != nil {
			t.Fatalf("Unable to connect to database %v: %v", dbName, firstError(err[:]))
		}
		if *backend_ldap {
			var err error
			ldap, err = NewAuthenticator_LDAP(&conx_ldap)
			if err != nil {
				t.Fatalf("Unable to connect to LDAP/AD %v", err)
			}
		}
	}

	if *backend_postgres {
		connectToDB(conx_postgres)
	} else {
		sessionDB = newDummySessionDB()
		permitDB = newDummyPermitDB()
		roleDB = newDummyRoleGroupDB()
		userStore = newDummyUserStore()
		if *backend_ldap {
			ldapTest = newDummyLdap()
			ldap = ldapTest

			permit := setup1_permit()
			permitDB.SetPermit(joeUserId, &permit)
			permitDB.SetPermit(samUserId, &permit)
		}
	}
	central := NewCentral(log.Stdout, ldap, userStore, permitDB, sessionDB, roleDB)

	// We add/merge the users to the userstore, and give the users permits
	if *backend_ldap {
		if !*backend_postgres {
			ldapTest.AddLdapUser(joeIdentity, joePwd, "joe@gmail.com", "Firstname", "Lastname", "Mobilenumber")
			ldapTest.AddLdapUser(jackIdentity, jackPwd, "jack@gmail.com", "Firstname", "Lastname", "Mobilenumber")
			ldapTest.AddLdapUser(SamIdentity, SamPwd, "Sam@gmail.com", "Firstname", "Lastname", "Mobilenumber")
			ldapTest.AddLdapUser(iHaveNoPermitIdentity, iHaveNoPermitPwd, "iHaveNoPermit@gmail.com", "Firstname", "Lastname", "Mobilenumber")
		}

		central.MergeTick()

		// Get joe userid to assign permit to
		userid, err := userStore.GetUserIdFromIdentity(joeIdentity)
		if err != nil {
			t.Errorf("Get userid for set permit failed: %v", err)
		}
		permit := setup1_permit()
		permitDB.SetPermit(userid, &permit)
	} else {
		if _, e := userStore.CreateIdentity(joeIdentity, "joeUsername", "joeName", "joeSurname", "joe084", joePwd); e != nil {
			t.Errorf("CreateIdentity failed: %v", e)
		}
		if _, e := userStore.CreateIdentity(jackIdentity, "jackUsername", "jackName", "jackSurname", "jack084", jackPwd); e != nil {
			t.Errorf("CreateIdentity failed: %v", e)
		}
		if _, e := userStore.CreateIdentity(SamIdentity, "SamUsername", "SamName", "SamSurname", "Sam084", SamPwd); e != nil {
			t.Errorf("CreateIdentity failed: %v", e)
		}
		if _, e := userStore.CreateIdentity(iHaveNoPermitIdentity, "iHaveNoPermitUsername", "iHaveNoPermitName", "iHaveNoPermitSurname", "iHaveNoPermit084", iHaveNoPermitPwd); e != nil {
			t.Errorf("CreateIdentity failed: %v", e)
		}
		permit := setup1_permit()
		permitDB.SetPermit(joeUserId, &permit)
		permitDB.SetPermit(samUserId, &permit)
	}

	return central
}

func Teardown(central *Central) {
	central.Close()
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
		"DROP TABLE IF EXISTS authuserpwd",
		"DROP TABLE IF EXISTS authuserstore",
		"DROP TABLE IF EXISTS migration_version",
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

func TestMergeLoad(t *testing.T) {
	if !*backend_ldap {
		return
	} else {
		t.Log("Testing ldap merge load")
		c := setup1(t)
		defer Teardown(c)
		c.ldapMergeTickerSeconds = (1 * time.Millisecond)
		err := c.StartMergeTicker()
		if err != nil {
			t.Errorf("Merge Ticker failed to start %v", err)
		}

		ticker := time.NewTicker(1 * time.Second)
		quit := make(chan bool)
		go func() {
			for {
				select {
				case <-ticker.C:
					_, _, err = c.Login(joeIdentity, joePwd)
					if err != nil {
						t.Errorf("Login failed %v", err)
					}
					_, err = c.GetAuthenticatorIdentities()
					if err != nil {
						t.Errorf("Error getting auth identities %v", err)
					}
				case <-quit:
					ticker.Stop()
					return
				}
			}
		}()
		time.Sleep(10 * time.Second)
		quit <- true
	}
}

func TestMergeLdap(t *testing.T) {
	if !*backend_ldap {
		return
	} else {
		t.Log("Testing ldap merge")
		c := setup1(t)
		defer Teardown(c)
		if *backend_postgres {
			userId, err := c.userStore.GetUserIdFromIdentity(joeIdentity)
			userPermit := setup1_permit()
			c.permitDB.SetPermit(userId, &userPermit)
			if err != nil {
				t.Fatalf("TestMergeLdap failed, could not get userid for: %v", joeIdentity)
			}
			if _, _, err := c.Login(joeIdentity, joePwd); err != nil {
				t.Fatalf("Login should have successed, but error was : %v", err)
			}
		} else {
			// Add new users to ldap, wait for merge then login
			ldapTest.AddLdapUser(tomIdentity, tomPwd, "tomh@hotgmail.com", "tom", "hanks", "08467531243")
			// Merge
			c.MergeTick()
			// Set permit to tom
			tomhPermit := setup1_permit()
			c.permitDB.SetPermit(tomUserId, &tomhPermit)
			if _, _, err := c.Login(tomIdentity, tomPwd); err != nil {
				t.Fatalf("Login should have succeeded, but error was : %v", err)
			}
			// Remove a user from ldap and wait for merge
			ldapTest.RemoveLdapUser(tomIdentity)
			// Merge
			c.MergeTick()
			if _, _, err := c.Login(tomIdentity, tomPwd); err == nil {
				t.Fatalf("Login should not have succeeded")
			}
		}
	}
}

func TestIdentityCaseSensitivity(t *testing.T) {
	if *backend_ldap {
		return
	} else {
		t.Log("Testing case sensitivity")
		c := setup1(t)
		defer Teardown(c)

		if _, e := c.CreateUserStoreIdentity("JOE", "JOEusername", "JOEfirstname", "JOElastname", "JOE084", "123"); e == nil || !isPrefix(ErrIdentityExists.Error(), e.Error()) {
			t.Errorf("CreateIdentity should fail because identities are case-insensitive. Instead, error is %v", e)
		}
	}
}

func TestRenameIdentity(t *testing.T) {
	if *backend_ldap {
		return
	} else {
		c := setup1(t)
		defer Teardown(c)

		// Fail to rename 'joe', because 'jack' already exists
		if err := c.RenameIdentity(joeIdentity, jackIdentity); err != ErrIdentityExists {
			t.Fatalf("Rename should not have succeeded")
		}

		// Fail to rename 'foo', because 'foo' does not exist
		if err := c.RenameIdentity("foo", "boo"); err != ErrIdentityAuthNotFound {
			t.Fatalf("Rename should have failed with ErrIdentityAuthNotFound")
		}

		// Succeed renaming 'joe' to 'sarah'
		session, _, _ := c.Login(joeIdentity, joePwd)
		if _, err := c.GetTokenFromSession(session); err != nil {
			t.Fatalf("Expected good login")
		}

		if err := c.RenameIdentity(joeIdentity, "sarah"); err != nil {
			t.Fatalf("Rename should have succeeded, but error was %v", err)
		}

		if _, err := c.GetTokenFromSession(session); err != ErrInvalidSessionToken {
			t.Fatalf("All sessions for 'joe' should have been invalidated by rename, %s", err)
		}

		if _, _, err := c.Login("sarah", joePwd); err != nil {
			t.Fatalf("Login as 'sarah' failed (%v)", err)
		}
	}
}

func TestResetPassword(t *testing.T) {
	if *backend_ldap {
		return
	} else {
		c := setup1(t)
		defer Teardown(c)

		if _, err := c.ResetPasswordStart(notFoundUserId, time.Now()); err != ErrIdentityAuthNotFound {
			t.Fatalf("ResetPasswordStart should fail with ErrIdentityAuthNotFound instead of %v", err)
		}
		if err := c.ResetPasswordFinish(joeUserId, "", "12345"); err != ErrInvalidPasswordToken {
			t.Fatalf("ResetPasswordFinish should fail with ErrInvalidPasswordToken instead of %v", err)
		}

		// Create two reset tokens, and verify that the first one is made invalid, and
		// the second one works.
		token1, err1 := c.ResetPasswordStart(joeUserId, time.Now().Add(30*time.Second))
		if err1 != nil || token1 == "" {
			t.Fatalf("Expected password reset to succeed, but (%v) (%v)", err1, token1)
		}
		token2, err2 := c.ResetPasswordStart(joeUserId, time.Now().Add(30*time.Second))
		if err2 != nil || token2 == "" {
			t.Fatalf("Expected password reset to succeed, but (%v) (%v)", err2, token2)
		}
		if token1 == token2 {
			t.Fatalf("Two successive password resets should not result in the same token")
		}
		if token, err := c.GetTokenFromIdentityPassword(joeIdentity, joePwd); err != nil || token == nil {
			t.Fatalf("Old password should remain valid until reset token has been used")
		}
		session, _, loginErr := c.Login(joeIdentity, joePwd)
		if loginErr != nil {
			t.Fatalf("Login should succeed instead of %v", loginErr)
		}
		if err := c.ResetPasswordFinish(notFoundUserId, token2, "yes"); err != ErrIdentityAuthNotFound {
			t.Fatalf("ResetPasswordFinish should fail with ErrIdentityAuthNotFound instead of %v", err)
		}
		if err := c.ResetPasswordFinish(joeUserId, token1, "yes"); err != ErrInvalidPasswordToken {
			t.Fatalf("ResetPasswordFinish on dead token should fail with ErrInvalidPasswordToken instead of %v", err)
		}
		if err := c.ResetPasswordFinish(joeUserId, token2, "12345"); err != nil {
			t.Fatalf("ResetPasswordFinish should succeed instead of %v", err)
		}
		if err := c.ResetPasswordFinish(joeUserId, token2, "12345"); err != ErrInvalidPasswordToken {
			t.Fatalf("ResetPasswordFinish a 2nd time should fail with ErrInvalidPasswordToken instead of %v", err)
		}
		if token, err := c.GetTokenFromIdentityPassword(joeIdentity, joePwd); err == nil || token != nil {
			t.Fatalf("Old password should be invalid by now")
		}
		if tokenFromOldSession, err := c.GetTokenFromSession(session); err == nil || tokenFromOldSession != nil {
			t.Fatalf("Old session should be invalid by now")
		}
		if token, err := c.GetTokenFromIdentityPassword(joeIdentity, "12345"); err != nil || token == nil {
			t.Fatalf("New password should succeed instead of %v", err)
		}

		// Test time expiry
		token3, _ := c.ResetPasswordStart(joeUserId, time.Now().Add(-3*time.Second))
		if err := c.ResetPasswordFinish(joeUserId, token3, "12345"); err != ErrPasswordTokenExpired {
			t.Fatalf("ResetPasswordFinish should have failed with ErrPasswordTokenExpired instead of %v", err)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	c := setup1(t)
	defer Teardown(c)

	expect_username_password := func(username, password, expectErrorStart, expectIdentity string) {
		// Authenticate
		token, err := c.GetTokenFromIdentityPassword(username, password)
		if (token == nil) != (err != nil) {
			t.Errorf("%v:%v -> (Token == nil) != (err != nil)", username, password)
		}
		if err != nil && strings.Index(err.Error(), expectErrorStart) != 0 {
			t.Errorf("%v:%v -> Expected '%v' prefix (but error starts with '%v')", username, password, expectErrorStart, err.Error())
		}
		// Get user id
		expectedUserId, _ := c.userStore.GetUserIdFromIdentity(expectIdentity)

		if token != nil && token.UserId != expectedUserId {
			t.Errorf("%v:%v -> Expected token identity '%v', returned '%v' ", username, password, expectedUserId, token.UserId)
		}
	}

	expect_username_password(joePwd, joeIdentity, ErrIdentityAuthNotFound.Error(), joePwd)
	expect_username_password(iHaveNoPermitIdentity, iHaveNoPermitPwd, ErrIdentityPermitNotFound.Error(), iHaveNoPermitIdentity)
	if *backend_ldap {

		expect_username_password(joeIdentity, "wrong", ErrInvalidCredentials.Error(), joeIdentity)

	} else {
		expect_username_password(joeIdentity, "wrong", ErrInvalidPassword.Error(), joeIdentity)
	}

	expect_username_password(joeIdentity, "", ErrInvalidPassword.Error(), joeIdentity)
	expect_username_password(joeIdentity, " ", ErrInvalidPassword.Error(), joeIdentity)
	expect_username_password("", "123", ErrIdentityEmpty.Error(), "")
	expect_username_password(" ", "123", ErrIdentityEmpty.Error(), "")
	expect_username_password(joeIdentity, joePwd, "", joeIdentity)
	expect_username_password("JOE", joePwd, "", joeIdentity)
	expect_username_password(SamIdentity, SamPwd, "", SamIdentity)
	expect_username_password("sam", SamPwd, "", SamIdentity)
}

func TestPermit(t *testing.T) {
	c := setup1(t)
	defer Teardown(c)
	token, e := c.GetTokenFromIdentityPassword(joeIdentity, joePwd)
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
	defer Teardown(c)

	doLogin := func(myid int, times int64, ch chan<- bool) {
		sessionKeys := make([]string, times)
		for iter := int64(0); iter < times; iter++ {
			//t.Logf("%v: %v/%v login\n", myid, iter, times)
			key, token, err := c.Login(joeIdentity, joePwd)
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
	if *backend_ldap {
		return
	} else {
		c := setup1(t)
		defer Teardown(c)
		perm1 := setup1_permit()
		perm2 := &Permit{}
		perm2_roles := [3]byte{5, 6, 7}
		perm2.Roles = perm2_roles[:]
		for nsessions := 1; nsessions < 100; nsessions *= 2 {
			// Restore password and permit
			if e := c.SetPassword(joeUserId, joePwd); e != nil {
				t.Fatalf("Password restore failed: %v (nsessions = %v)", e, nsessions)
			}
			if e := c.SetPermit(joeUserId, &perm1); e != nil {
				t.Fatalf("Permit restore failed: %v", e)
			}

			keys := make([]string, nsessions)
			tokens := make([]*Token, nsessions)
			for i := 0; i < nsessions; i++ {
				keys[i], tokens[i], _ = c.Login(joeIdentity, joePwd)
				if !bytes.Equal(tokens[i].Permit.Roles, perm1.Roles) {
					t.Fatalf("Permits not equal %v %v\n", tokens[i].Permit.Roles, perm1.Roles)
				}
			}
			// Set a new permit
			c.SetPermit(joeUserId, perm2)
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
			c.SetPassword(joeUserId, "456")
			for i := 0; i < nsessions; i++ {
				_, e := c.GetTokenFromSession(keys[i])
				if e == nil {
					t.Fatalf("Session not correctly invalidated after password change")
				}
			}
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	c := setup1(t)
	defer Teardown(c)
	c.NewSessionExpiresAfter = time.Millisecond * 500
	key, _, _ := c.Login(joeIdentity, joePwd)
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
	defer Teardown(c)
	c.MaxActiveSessions = 1

	// Login first time
	key1, _, _ := c.Login(joeIdentity, joePwd)
	_, err := c.GetTokenFromSession(key1)
	if err != nil {
		t.Fatalf("Expected key1 to be valid")
	}

	// Login second time. After this, key1 must be invalid
	key2, _, _ := c.Login(joeIdentity, joePwd)
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
	defer Teardown(c)
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
		sessionkey := login(joeIdentity, joePwd)
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
	defer Teardown(c)
	key, _, _ := c.Login(joeIdentity, joePwd)
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

func TestUpdateIdentity(t *testing.T) {
	c := setup1(t)
	defer Teardown(c)

	newEmail := "newEmail"
	newUsername := "newUsername"
	newName := "newName"
	newSurname := "newSurname"
	newMobile := "newMobile"

	if err := c.UpdateIdentity(notFoundUserId, newEmail, newUsername, newName, newSurname, newMobile); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestUpdateIdentity failed: Expected ErrIdentityAuthNotFound, but got: %v", err)
	}

	if err := c.UpdateIdentity(joeUserId, newEmail, newUsername, newName, newSurname, newMobile); err != nil {
		t.Fatalf("Update should not have failed: %v", err)
	}

	users, err := c.GetAuthenticatorIdentities()
	if err != nil {
		t.Fatalf("TestUpdateIdentity failed: %v", err)
	}

	updateSuccess := false
	for _, user := range users {
		if user.UserId == joeUserId && CanonicalizeIdentity(user.Email) == CanonicalizeIdentity(newEmail) && user.Username == newUsername && user.Firstname == newName && user.Lastname == newSurname && user.Mobilenumber == newMobile {
			updateSuccess = true
			break
		}
	}
	if !updateSuccess {
		t.Fatalf("TestUpdateIdentity failed: After update, failed to find updated user")
	}
}

func TestArchiveIdentity(t *testing.T) {
	if *backend_ldap {
		return
	} else {
		c := setup1(t)
		defer Teardown(c)

		if err := c.ArchiveIdentity(notFoundUserId); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed: Expected ErrIdentityAuthNotFound, but got: %v", err)
		}

		if err := c.ArchiveIdentity(joeUserId); err != nil {
			t.Fatalf("Archive should not have failed: %v", err)
		}

		users, e := c.GetAuthenticatorIdentities()
		if e != nil {
			t.Fatalf("TestArchiveIdentity failed: %v", e)
		}

		archiveSuccess := true
		for _, user := range users {
			if user.UserId == joeUserId {
				archiveSuccess = false
				break
			}
		}
		if !archiveSuccess {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be found")
		}

		// Try to authenticate with archived user
		if _, err := c.GetTokenFromIdentityPassword("joe", "123"); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to authenticate: %v", err)
		}

		// Try to update archived user
		if err := c.UpdateIdentity(joeUserId, "newEmail", "newUsername", "newName", "newSurname", "newMobile"); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be updated: %v", err)
		}

		// Try resetting password of archived user
		if _, err := c.ResetPasswordStart(joeUserId, time.Now()); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be reset password: %v", err)
		}

		// Try renaming email of archived user
		if err := c.RenameIdentity(joeIdentity, "newJoe"); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be rename identity: %v", err)
		}
	}
}
