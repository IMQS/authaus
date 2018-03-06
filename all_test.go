package authaus

import (
	"bytes"
	"database/sql"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/IMQS/log"
	"golang.org/x/crypto/scrypt"
)

/*
NOTE: Some of these tests stress concurrency, so you must run them with at least -test.cpu 2

TODO: Add test that verifies that SetPassword does not create an identity if that identity does not already exist

Create a test Postgres database:
	create role authaus_test login password 'authaus_test';
	create database authaus_test owner = authaus_test;

Suggested test runs that you should do:

	-- Test using maps/arrays mocking the backend:
	go test -race github.com/IMQS/authaus -test.cpu 2 -run TestAuth

	-- Test using postgres as the backend:
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_postgres -run TestAuth

	-- Test using postgres as the backend and connecting to our LDAP system:
	*NOTE This test may only be run when on the IMQS domain, else it will fail
	go test -race github.com/IMQS/authaus -test.cpu 2 -backend_ldap -run TestIntegratedLdap


I'm not sure that testing without the race detector adds any value.
*/

var backend_postgres = flag.Bool("backend_postgres", false, "Run tests against Postgres backend")
var backend_ldap = flag.Bool("backend_ldap", false, "Run tests against LDAP backend")

// These are hard-coded identities for unit test predictability
var joeEmail = "joe@email.test"
var jackEmail = "jack@email.test"
var samEmail = "Sam@email.test"
var iHaveNoPermitIdentity = "iHaveNoPermit"
var testLdapIdentity = "TestLdapUser"
var imqsLdapIdentity = "LDAP"

// These are hard-coded passwords for unit test predictability
var joePwd = "1234abcd"
var jackPwd = "abcd1234"
var SamPwd = "12341234"
var iHaveNoPermitPwd = "1234wxyz"
var testLdapPwd = "TestLdapUser"
var imqsLdapPwd = "TestLDAP4IMQS"

// These hard-coded UserId values are predictable because we always drop & recreate the postgres backend when running
// tests, so we know that our IDs always start at 1
var joeUserId UserId = 1
var imqsLdapUserId UserId = 1
var jackUserId UserId = 2
var samUserId UserId = 3
var iHaveNoPermit UserId = 4
var notFoundUserId UserId = 999
var ldapTest *dummyLdap

var conx_postgres = DBConnection{
	Driver:   "postgres",
	Host:     "localhost",
	Port:     5432,
	Database: "unit_test_authaus",
	User:     "unit_test_user",
	Password: "unit_test_password",
	SSL:      false,
}

var conx_ldap = ConfigLDAP{
	Encryption:       "",
	LdapDomain:       "imqs.local",
	LdapHost:         "imqs.local",
	LdapPassword:     imqsLdapPwd,
	LdapUsername:     (imqsLdapIdentity + "@imqs.local"),
	LdapPort:         389,
	LdapTickerTime:   5,
	BaseDN:           "dc=imqs,dc=local",
	SysAdminEmail:    "joeAdmin@example.com",
	LdapSearchFilter: "(&(objectCategory=person)(objectClass=user))",
}

func isBackendLdapTest() bool {
	return *backend_ldap
}

func isBackendPostgresTest() bool {
	return *backend_postgres
}

func setupPermit() Permit {
	p := Permit{}
	r := [2]byte{1, 2}
	p.Roles = r[:]
	return p
}

func connectToDB(conn DBConnection, t *testing.T, userStore *UserStore, sessionDB *SessionDB, permitDB *PermitDB, roleDB *RoleGroupDB) {
	dbName := conn.Host + ":" + conn.Database

	if ecreate := SqlCreateDatabase(&conn); ecreate != nil {
		t.Fatalf("Unable to create test database: %v: %v", dbName, ecreate)
	}

	if db, errdb := conn.Connect(); errdb != nil {
		t.Fatalf("Unable to connect to database %v: %v", dbName, errdb)
	} else {
		if err := sqlDeleteAllTables(db); err != nil {
			t.Fatalf("Unable to wipe database %v: %v", dbName, err)
		}

		if err := RunMigrations(&conn); err != nil {
			t.Fatalf("Unable to run migrations: %v", err)
		}
	}

	var err [4]error
	*(userStore), err[0] = NewUserStoreDB_SQL(&conn)
	*(sessionDB), err[1] = NewSessionDB_SQL(&conn)
	*(permitDB), err[2] = NewPermitDB_SQL(&conn)
	*(roleDB), err[3] = NewRoleGroupDB_SQL(&conn)
	if firstError(err[:]) != nil {
		t.Fatalf("Unable to connect to database %v: %v", dbName, firstError(err[:]))
	}
}

func getCentral(t *testing.T) *Central {
	var userStore UserStore
	var sessionDB SessionDB
	var permitDB PermitDB
	var roleDB RoleGroupDB

	if isBackendPostgresTest() || isBackendLdapTest() {
		connectToDB(conx_postgres, t, &userStore, &sessionDB, &permitDB, &roleDB)
	} else {
		sessionDB = newDummySessionDB()
		permitDB = newDummyPermitDB()
		roleDB = newDummyRoleGroupDB()
		userStore = newDummyUserStore()

	}

	return NewCentral(log.Stdout, nil, userStore, permitDB, sessionDB, roleDB)
}

func setup(t *testing.T) *Central {
	central := getCentral(t)

	now := time.Now().UTC()

	joeUser := AuthUser{
		Email:           joeEmail,
		Username:        "joeUsername",
		Firstname:       "joeFirstname",
		Lastname:        "joeLastname",
		Mobilenumber:    "joe084",
		Telephonenumber: "joe021",
		Remarks:         "joe test",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	if _, e := central.userStore.CreateIdentity(&joeUser, joePwd); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	jackUser := AuthUser{
		Email:           jackEmail,
		Username:        "jackUsername",
		Firstname:       "jackFirstname",
		Lastname:        "jackLastname",
		Mobilenumber:    "jack084",
		Telephonenumber: "jack021",
		Remarks:         "jack test",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	if _, e := central.userStore.CreateIdentity(&jackUser, jackPwd); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}

	samUser := AuthUser{
		Email:           samEmail,
		Username:        "",
		Firstname:       "SamName",
		Lastname:        "SamSurname",
		Mobilenumber:    "Sam084",
		Telephonenumber: "Sam021",
		Remarks:         "Sam test",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	if _, e := central.userStore.CreateIdentity(&samUser, SamPwd); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}

	iHaveNoPermitUser := AuthUser{
		Email:           iHaveNoPermitIdentity,
		Username:        "",
		Firstname:       "iHaveNoPermitName",
		Lastname:        "iHaveNoPermitSurname",
		Mobilenumber:    "SamiHaveNoPermit084084",
		Telephonenumber: "iHaveNoPermit021",
		Remarks:         "iHaveNoPermit test",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	if _, e := central.userStore.CreateIdentity(&iHaveNoPermitUser, iHaveNoPermitPwd); e != nil {
		t.Errorf("CreateIdentity failed: %v", e)
	}
	permit := setupPermit()
	central.permitDB.SetPermit(joeUserId, &permit)
	central.permitDB.SetPermit(samUserId, &permit)

	return central
}

func setupLdap(t *testing.T) *Central {
	central := getCentral(t)

	if isBackendLdapTest() {
		var err error
		central.ldap, err = NewAuthenticator_LDAP(&conx_ldap)
		if err != nil {
			t.Fatalf("Unable to connect to LDAP %v", err)
		}

		central.MergeTick()

		// Setup permissions
		user, err := central.userStore.GetUserFromIdentity(imqsLdapIdentity)
		if err != nil {
			t.Errorf("Get userid for set permit failed: %v", err)
		}
		permit := setupPermit()
		central.permitDB.SetPermit(user.UserId, &permit)
	} else {
		ldapTest = newDummyLdap()
		central.ldap = ldapTest

		ldapTest.AddLdapUser(imqsLdapIdentity, imqsLdapPwd, "joe@gmail.com", "Firstname", "Lastname", "Mobilenumber")
		central.MergeTick()

		// Setup permissions
		permit := setupPermit()
		central.permitDB.SetPermit(imqsLdapUserId, &permit)
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
		"DROP TABLE IF EXISTS authuser",
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Integrated LDAP Tests
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestIntegratedLdapAuthenticateFailure(t *testing.T) {
	t.Log("Testing ldap logging in with anonymous bind")
	c := setupLdap(t)
	defer Teardown(c)

	user, err := c.GetUserFromIdentity(imqsLdapIdentity)
	if err != nil {
		t.Errorf("An unexpected error occured getting userid for identity: %v", imqsLdapIdentity)
	}

	joePermit := setupPermit()
	c.permitDB.SetPermit(user.UserId, &joePermit)

	if _, _, err := c.Login(imqsLdapIdentity, "invalidpassword"); err != nil {
		if !strings.Contains(err.Error(), ErrInvalidPassword.Error()) {
			t.Fatalf("Login should have failed with invalid password, but error was: %v", err)
		}
	}

	if _, _, err := c.Login("somerandomusername", "invalidpassword"); err != nil {
		if !strings.Contains(err.Error(), ErrIdentityAuthNotFound.Error()) {
			t.Fatalf("Login should have failed with identity not found, but error was: %v", err)
		}
	}
}

// We do not allow anonymous binds through Login()
func TestIntegratedLdapLoginWithAnonymousBind(t *testing.T) {
	t.Log("Testing ldap logging in with anonymous bind")
	c := setupLdap(t)
	defer Teardown(c)

	user, err := c.GetUserFromIdentity(imqsLdapIdentity)
	if err != nil {
		t.Errorf("An unexpected error occured getting userid for identity: %v", imqsLdapIdentity)
	}

	joePermit := setupPermit()
	c.permitDB.SetPermit(user.UserId, &joePermit)

	// Note, we are logging in with no password
	if _, _, err := c.Login(imqsLdapIdentity, ""); err != nil {
		if !strings.Contains(err.Error(), ErrInvalidPassword.Error()) {
			t.Fatalf("Login should have failed with invalid password, but error was: %v", err)
		}
	}
}

// This test makes sure that after a connection recovery, all users do not get deleted by merge.
// The last part of the merge deletes users that are in the Imqsauth DB, and not on LDAP. If the connection fails,
// the LDAP array will contain nothing, and compare IMQS users with an empty array, deleting all LDAP users
// from the Imqsauth DB.
func TestIntegratedLdapConnectionRecovery(t *testing.T) {
	t.Log("Testing ldap connection recovery")
	c := setupLdap(t)
	defer Teardown(c)

	user, err := c.GetUserFromIdentity(imqsLdapIdentity)
	if err != nil {
		t.Errorf("An unexpected error occured getting userid for identity: %v", imqsLdapIdentity)
	}

	joePermit := setupPermit()
	c.permitDB.SetPermit(user.UserId, &joePermit)

	if _, _, err := c.Login(imqsLdapIdentity, imqsLdapPwd); err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	// Force connection to LDAP to fail
	host := conx_ldap.LdapHost
	conx_ldap.LdapHost = "invalid.host"
	c.MergeTick()

	conx_ldap.LdapHost = host
	c.MergeTick()

	if _, _, err := c.Login(imqsLdapIdentity, imqsLdapPwd); err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}
}

func TestIntegratedLdapMergeLoad(t *testing.T) {
	t.Log("Testing ldap merge load")
	c := setupLdap(t)
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
				_, _, err = c.Login(imqsLdapIdentity, imqsLdapPwd)
				if err != nil {
					t.Errorf("Login failed %v", err)
				}
				_, err = c.GetAuthenticatorIdentities(GetIdentitiesFlagNone)
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LDAP Unit Tests
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestAuthLdapMerge(t *testing.T) {
	t.Log("Testing ldap merge")
	c := setupLdap(t)
	defer Teardown(c)

	// Test merge, when adding and removing from ldap
	ldapTest.AddLdapUser(testLdapIdentity, testLdapPwd, "tomh@hotgmail.com", "tom", "hanks", "08467531243")
	c.MergeTick()

	testLdapUser, err := c.GetUserFromIdentity(testLdapIdentity)
	if err != nil {
		t.Fatalf("TestMergeLdap failed unexpectedly, error: %v", err)
	}
	tomhPermit := setupPermit()
	c.permitDB.SetPermit(testLdapUser.UserId, &tomhPermit)

	if _, _, err := c.Login(testLdapIdentity, testLdapPwd); err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	ldapTest.RemoveLdapUser(testLdapIdentity)
	c.MergeTick()

	if _, _, err := c.Login(testLdapIdentity, testLdapPwd); err == nil {
		t.Fatalf("Login should not have succeeded")
	}

	// Test merge when updating ldap user
	ldapTest.AddLdapUser(testLdapIdentity, testLdapPwd, "tomh@hotgmail.com", "tom", "hanks", "08467531243")
	c.MergeTick()

	newEmail := "newEmail"
	newName := "newName"
	newSurname := "newSurname"
	newMobile := "newMobile"
	ldapTest.UpdateLdapUser(testLdapIdentity, newEmail, newName, newSurname, newMobile)

	c.MergeTick()

	testLdapUser, err = c.GetUserFromIdentity(testLdapIdentity)
	if err != nil {
		t.Fatalf("TestMergeLdap failed, error: %v", err)
	}
	if !(testLdapUser.Email == newEmail && testLdapUser.Firstname == newName && testLdapUser.Lastname == newSurname && testLdapUser.Mobilenumber == newMobile) {
		t.Fatalf("Expected merge update to succeed, but failed, as not all attributes were updated")
	}

	// Test merge when ldap username exists on the imqs system (local pg DB).
	// After merging, we should find the username already exist. We will update
	// the IMQS user with that username to become of type LDAPuser, so we test against that
	newUser := "IMQSUserWithUsername"
	now := time.Now().UTC()

	user := AuthUser{
		Email:           newUser,
		Username:        newUser,
		Firstname:       "firstname",
		Lastname:        "lastname",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
	}

	_, e := c.CreateUserStoreIdentity(&user, "pwd")
	if e != nil {
		t.Fatalf("TestMergeLdap failed, create user: %v", e)
	}

	joeUser, err := c.GetUserFromIdentity(newUser)
	if err != nil {
		t.Fatalf("TestMergeLdap failed, error: %v", err)
	}
	if joeUser.Type != UserTypeDefault {
		t.Fatalf("TestMergeLdap failed, expected newly created user to be IMQS user type (0), instead %v", joeUser.Type)
	}

	ldapTest.AddLdapUser(newUser, "pwd", newUser, "tom", "hanks", "08467531243")
	c.MergeTick()

	joeUser, err = c.GetUserFromIdentity(newUser)
	if err != nil {
		t.Fatalf("TestMergeLdap failed, error: %v", err)
	}
	if joeUser.Type != UserTypeLDAP {
		t.Fatalf("TestMergeLdap failed, expected merged user to be LDAP user type (1), instead %v", joeUser.Type)
	}
}

// Test Ldap merging when the new Ldap user have a space in the Username or Email.
// This used to cause an "Identity already exists" error before the fix.
// This scenario seems to be extremely unlikely to occur, but not impossible.
func TestAuthLdapMergeSpace(t *testing.T) {
	t.Log("Testing ldap merge including spaces")
	c := setupLdap(t)
	defer Teardown(c)

	newUserEmail := "IMQSUserWithEmail@imqsemail.co.za"
	now := time.Now().UTC()

	user := AuthUser{
		Email:           newUserEmail,
		Username:        "",
		Firstname:       "firstname",
		Lastname:        "lastname",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}

	_, e := c.CreateUserStoreIdentity(&user, "pwd")
	if e != nil {
		t.Fatalf("TestMergeLdap failed, create user: %v", e)
	}

	johnUser, err := c.GetUserFromIdentity(newUserEmail)
	if err != nil {
		t.Fatalf("TestMergeLdap failed, error: %v", err)
	}
	if johnUser.Type != UserTypeDefault {
		t.Fatalf("TestMergeLdap failed, expected newly created user to be IMQS user type (0), instead %v", johnUser.Type)
	}

	ldapTest.AddLdapUser("LdapUsername", "pwd", newUserEmail+" ", "Tom", "hanks", "08467531243")
	c.MergeTick()

	johnUser, err = c.GetUserFromIdentity(newUserEmail)
	if err != nil {
		t.Fatalf("TestMergeLdap failed, error: %v", err)
	}
	if johnUser.Type != UserTypeLDAP {
		t.Fatalf("TestMergeLdap failed, expected merged user to be LDAP user type (1), instead %v", johnUser.Type)
	}
}

// This tests that if an IMQS user exists that has the same email address as an LDAP user during
// an LDAP merge, that it converts the IMQS User to be an LDAP user.
func TestAuthLdapIMQSUserToLDAPUserConversion(t *testing.T) {
	t.Log("Testing IMQS user conversion")
	c := setupLdap(t)
	defer Teardown(c)

	// We need to add a new user to ldap and to imqs.
	newEmail := "peter@example.com"
	newLDAPUsername := "peter"
	// We want the passwords to be different for testing purposes.
	newIMQSPwd := "petersIMQSpassword"
	newLDAPPwd := "peterLDAPpassword"

	now := time.Now().UTC()

	// Create user in IMQS and LDAP
	user := AuthUser{
		Email:           newEmail,
		Username:        "",
		Firstname:       "",
		Lastname:        "",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
	}
	peterUserId, err := c.CreateUserStoreIdentity(&user, newIMQSPwd)
	if err != nil {
		t.Fatalf("Create user should have succeeded, but error was : %v", err)
	}
	ldapTest.AddLdapUser(newLDAPUsername, newLDAPPwd, newEmail, "", "", "")

	// Test IMQS user login.
	permit := setupPermit()
	c.permitDB.SetPermit(peterUserId, &permit)
	_, _, err = c.Login(newEmail, newIMQSPwd)
	if err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	// The IMQS to LDAP user conversion will now take place, and login with the IMQS user's credentials
	// should no longer work. However, login with the LDAP user should work.
	c.MergeTick()

	_, _, err = c.Login(newEmail, newIMQSPwd)
	if err == nil {
		t.Fatalf("Login should have failed")
	}

	// Login with both email address and username of the LDAP account to make sure the account is
	// one and the same.
	_, emailLoginToken, err := c.Login(newEmail, newLDAPPwd)
	if err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}
	_, usernameLoginToken, err := c.Login(newLDAPUsername, newLDAPPwd)
	if err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	// We compare user ids to make sure it is all the same user account.
	if peterUserId != emailLoginToken.UserId && peterUserId != usernameLoginToken.UserId {
		t.Fatalf("Expected user ids to match")
	}
}

// This tests that if an IMQS user and an LDAP user both have email addresses or usernames containing empty strings, they will not
// override each other
func TestAuthLdapUsernamesAndEmailsWithEmptyStringsShouldNotMerge(t *testing.T) {
	t.Log("Testing IMQS username or email with empty strings cases")
	c := setupLdap(t)
	defer Teardown(c)

	emptyStringEmail := ""
	emptyStringUsername := ""
	imqsUsername := "Peter"
	imqsEmail := "Peter@test.co.za"
	imqsPassword := "test123"
	ldapUsername := "John"
	ldapEmail := "John@haha.co.za"
	now := time.Now().UTC()

	// Testing blank email case
	blankEmailUser := AuthUser{
		Email:           emptyStringEmail,
		Username:        imqsUsername,
		Firstname:       "",
		Lastname:        "",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
	}
	imqsUserId, err := c.CreateUserStoreIdentity(&blankEmailUser, imqsPassword)
	if err != nil {
		t.Fatalf("Create user should have succeeded, but error was : %v", err)
	}
	ldapTest.AddLdapUser(ldapUsername, "", emptyStringEmail, "", "", "")

	permit := setupPermit()
	c.permitDB.SetPermit(imqsUserId, &permit)
	_, _, err = c.Login(imqsUsername, imqsPassword)
	if err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	// This merge should have zero affect, no merge on this user should take place
	c.MergeTick()
	_, _, err = c.Login(imqsUsername, imqsPassword)
	if err != nil {
		t.Fatalf("Login should have succeeded. This probably means the merge took place, and should not have. Error was: %v", err)
	}

	// Testing blank username case
	blankUsernameUser := AuthUser{
		Email:           imqsEmail,
		Username:        emptyStringUsername,
		Firstname:       "",
		Lastname:        "",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
	}
	imqsUserId, err = c.CreateUserStoreIdentity(&blankUsernameUser, imqsPassword)
	if err != nil {
		t.Fatalf("Create user should have succeeded, but error was : %v", err)
	}
	ldapTest.AddLdapUser(emptyStringUsername, "", ldapEmail, "", "", "")

	c.permitDB.SetPermit(imqsUserId, &permit)
	_, _, err = c.Login(imqsEmail, imqsPassword)
	if err != nil {
		t.Fatalf("Login should have succeeded, but error was : %v", err)
	}

	// This merge should have zero affect, no merge on this user should take place
	c.MergeTick()
	_, _, err = c.Login(imqsEmail, imqsPassword)
	if err != nil {
		t.Fatalf("Login should have succeeded. This probably means the merge took place, and should not have. Error was: %v", err)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Normal Auth Tests
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestAuthIdentityCaseSensitivity(t *testing.T) {
	t.Log("Testing case sensitivity")
	c := setup(t)
	defer Teardown(c)
	now := time.Now().UTC()
	user := AuthUser{
		Email:           "JOE@email.test",
		Username:        "JOE",
		Firstname:       "JOEfirstname",
		Lastname:        "JOElastname",
		Mobilenumber:    "JOE084",
		Telephonenumber: "JOE021",
		Remarks:         "JOEremarks",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
	}
	if _, e := c.CreateUserStoreIdentity(&user, "123"); e == nil || !isPrefix(ErrIdentityExists.Error(), e.Error()) {
		t.Errorf("CreateIdentity should fail because identities are case-insensitive. Instead, error is %v", e)
	}
}

func TestAuthLoginCaseSensitivity(t *testing.T) {
	t.Log("Testing Login case sensitivity")
	c := setup(t)
	defer Teardown(c)

	const joeCapitalizedIdentity = "JOE@email.test"

	_, token, e := c.Login(joeCapitalizedIdentity, joePwd)
	if e != nil {
		t.Fatalf("An unexpected error occurred: %v", e)
	}
	if joeEmail != token.Identity {
		t.Errorf("Identities should match")
	}
}

// TODO This test should be removed, as rename identity is now a deprecated function, replaced in in May 2016 by UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string)
func TestAuthRenameIdentity(t *testing.T) {
	c := setup(t)
	defer Teardown(c)

	// Fail to rename 'joe', because 'jack' already exists
	if err := c.RenameIdentity(joeEmail, jackEmail); err != ErrIdentityExists {
		t.Fatalf("Rename should not have succeeded")
	}

	// Fail to rename 'foo', because 'foo' does not exist
	if err := c.RenameIdentity("foo", "boo"); err != ErrIdentityAuthNotFound {
		t.Fatalf("Rename should have failed with ErrIdentityAuthNotFound")
	}

	// Succeed renaming 'joe' to 'sarah'
	session, _, _ := c.Login(joeEmail, joePwd)
	if _, err := c.GetTokenFromSession(session); err != nil {
		t.Fatalf("Expected good login")
	}

	if err := c.RenameIdentity(joeEmail, "sarah"); err != nil {
		t.Fatalf("Rename should have succeeded, but error was %v", err)
	}

	if _, err := c.GetTokenFromSession(session); err != ErrInvalidSessionToken {
		t.Fatalf("All sessions for 'joe' should have been invalidated by rename, %s", err)
	}

	if _, _, err := c.Login("sarah", joePwd); err != nil {
		t.Fatalf("Login as 'sarah' failed (%v)", err)
	}
}

func TestAuthResetPassword(t *testing.T) {
	c := setup(t)
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
	if token, err := c.GetTokenFromIdentityPassword(joeEmail, joePwd); err != nil || token == nil {
		t.Fatalf("Old password should remain valid until reset token has been used, but (%v)", err)
	}
	session, _, loginErr := c.Login(joeEmail, joePwd)
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
	if token, err := c.GetTokenFromIdentityPassword(joeEmail, joePwd); err == nil || token != nil {
		t.Fatalf("Old password should be invalid by now")
	}
	if tokenFromOldSession, err := c.GetTokenFromSession(session); err == nil || tokenFromOldSession != nil {
		t.Fatalf("Old session should be invalid by now")
	}
	if token, err := c.GetTokenFromIdentityPassword(joeEmail, "12345"); err != nil || token == nil {
		t.Fatalf("New password should succeed instead of %v", err)
	}

	// Test time expiry
	token3, _ := c.ResetPasswordStart(joeUserId, time.Now().Add(-3*time.Second))
	if err := c.ResetPasswordFinish(joeUserId, token3, "12345"); err != ErrPasswordTokenExpired {
		t.Fatalf("ResetPasswordFinish should have failed with ErrPasswordTokenExpired instead of %v", err)
	}
}

func TestAuthBasicAuth(t *testing.T) {
	c := setup(t)

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
		expectedUser, _ := c.userStore.GetUserFromIdentity(expectIdentity)

		if token != nil && token.UserId != expectedUser.UserId {
			t.Errorf("%v:%v -> Expected token identity '%v', returned '%v' ", username, password, expectedUser.UserId, token.UserId)
		}
	}

	expect_username_password(joePwd, joeEmail, ErrIdentityAuthNotFound.Error(), joePwd)
	expect_username_password(iHaveNoPermitIdentity, iHaveNoPermitPwd, ErrIdentityPermitNotFound.Error(), iHaveNoPermitIdentity)
	expect_username_password(joeEmail, "wrong", ErrInvalidPassword.Error(), joeEmail)
	expect_username_password(joeEmail, "", ErrInvalidPassword.Error(), joeEmail)
	expect_username_password(joeEmail, " ", ErrInvalidPassword.Error(), joeEmail)
	expect_username_password("", "123", ErrIdentityEmpty.Error(), "")
	expect_username_password(" ", "123", ErrIdentityEmpty.Error(), "")
	expect_username_password(joeEmail, joePwd, "", joeEmail)
	expect_username_password("JOE", joePwd, "", joeEmail)
	expect_username_password(samEmail, SamPwd, "", samEmail)
	expect_username_password("sam", SamPwd, "", samEmail)

	Teardown(c)

	// When we use LDAP backend, the users with authusertype LDAP will be authenticated by LDAP. Lets
	// create a user with an IMQS type and authenticate with the LDAP backend
	c = setupLdap(t)
	defer Teardown(c)
	now := time.Now().UTC()

	user := AuthUser{
		Email:           testLdapIdentity,
		Username:        "tomh",
		Firstname:       "Tom",
		Lastname:        "Hanks",
		Mobilenumber:    "",
		Telephonenumber: "",
		Remarks:         "",
		Created:         now,
		CreatedBy:       0,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	userId, err := c.userStore.CreateIdentity(&user, testLdapPwd)
	if err != nil {
		t.Errorf("TestBasicAuth failed, expected create IMQS user success, but instead error (%v)", err)
	}
	permit := setupPermit()
	c.permitDB.SetPermit(userId, &permit)

	expect_username_password(testLdapIdentity, testLdapPwd, "", testLdapIdentity)
	expect_username_password(testLdapIdentity, "invalidpassword", ErrInvalidPassword.Error(), testLdapIdentity)
}

func TestAuthPermit(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	token, e := c.GetTokenFromIdentityPassword(joeEmail, joePwd)
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
func TestAuthLoad(t *testing.T) {
	c := setup(t)
	defer Teardown(c)

	doLogin := func(myid int, times int64, ch chan<- bool) {
		sessionKeys := make([]string, times)
		for iter := int64(0); iter < times; iter++ {
			//t.Logf("%v: %v/%v login\n", myid, iter, times)
			key, token, err := c.Login(joeEmail, joePwd)
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
	if isBackendPostgresTest() {
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
func TestAuthPermitChange(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	perm1 := setupPermit()
	perm2 := &Permit{}
	perm2_roles := [3]byte{5, 6, 7}
	perm2.Roles = perm2_roles[:]
	for nsessions := 1; nsessions < 100; nsessions *= 2 {
		c.InvalidateSessionsForIdentity(joeUserId)
		if e := c.SetPermit(joeUserId, &perm1); e != nil {
			t.Fatalf("Permit restore failed: %v", e)
		}

		keys := make([]string, nsessions)
		tokens := make([]*Token, nsessions)
		for i := 0; i < nsessions; i++ {
			keys[i], tokens[i], _ = c.Login(joeEmail, joePwd)
			if !bytes.Equal(tokens[i].Permit.Roles, perm1.Roles) {
				t.Fatalf("Permits not equal %v %v\n", tokens[i].Permit.Roles, perm1.Roles)
			}
		}
		// Set a new permit
		if e := c.SetPermit(joeUserId, perm2); e != nil {
			t.Fatalf("Setting restore failed: %v", e)
		}
		for i := 0; i < nsessions; i++ {
			token, e := c.GetTokenFromSession(keys[i])
			if e != nil {
				t.Fatalf("Permit from session not found after permit change: %v\n", e)
			}
			if !bytes.Equal(token.Permit.Roles, perm2.Roles) {
				t.Fatalf("Permits not equal %v %v\n", token.Permit.Roles, perm2.Roles)
			}
		}

		// This invalidates all sessions.
		c.InvalidateSessionsForIdentity(joeUserId)
		for i := 0; i < nsessions; i++ {
			_, e := c.GetTokenFromSession(keys[i])
			if e == nil {
				t.Fatalf("Session not correctly invalidated after password change")
			}
		}
	}
}

func TestAuthSessionExpiry(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	testSessionExpiry := func(inMemCache bool) {
		c.NewSessionExpiresAfter = time.Millisecond * 500
		key, _, _ := c.Login(joeEmail, joePwd)
		if !inMemCache {
			// Clear in memory session cache, relying on the db to get cache
			c.debugEnableSessionDB(false)
			c.sessionDB.Delete(key)
			c.debugEnableSessionDB(true)
		}
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
	// In cache
	testSessionExpiry(true)
	// In Postgres
	testSessionExpiry(false)
	//t.Fail()
}

func TestAuthMaxSessionLimit(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	c.MaxActiveSessions = 1

	// Login first time
	key1, _, _ := c.Login(joeEmail, joePwd)
	_, err := c.GetTokenFromSession(key1)
	if err != nil {
		t.Fatalf("Expected key1 to be valid")
	}

	// Login second time. After this, key1 must be invalid
	key2, _, _ := c.Login(joeEmail, joePwd)
	_, err = c.GetTokenFromSession(key1)
	if err == nil {
		t.Fatalf("Expected key1 to be invalid")
	}
	_, err = c.GetTokenFromSession(key2)
	if err != nil {
		t.Fatalf("Expected key2 to be valid")
	}
}

func TestAuthDBSession(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	c.MaxActiveSessions = 1

	// Login first time
	key, _, _ := c.Login(joeEmail, joePwd)
	token1, err := c.GetTokenFromSession(key)
	if err != nil {
		t.Fatalf("Expected key to be valid")
	}

	// Clear in memory session cache, relying on the db to get cache
	c.debugEnableSessionDB(false)
	c.sessionDB.Delete(key)
	c.debugEnableSessionDB(true)

	token2, err := c.GetTokenFromSession(key)
	if err != nil {
		t.Fatalf("Expected key to be valid")
	}

	// Compare tokens
	if !(token1.UserId == token2.UserId && token1.Identity == token2.Identity && token1.Expires.Unix() == token2.Expires.Unix() && token1.Permit.Serialize() == token2.Permit.Serialize()) {
		t.Fatalf("Tokens must match")
	}
}

func TestAuthSessionCacheEviction(t *testing.T) {
	c := setup(t)
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
		sessionkey := login(joeEmail, joePwd)
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

func TestAuthSessionDelete(t *testing.T) {
	c := setup(t)
	defer Teardown(c)
	key, _, _ := c.Login(joeEmail, joePwd)
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

func TestAuthUpdateIdentity(t *testing.T) {
	c := setup(t)
	defer Teardown(c)

	newEmail := "newEmail"
	newUsername := "newUsername"
	newName := "newName"
	newSurname := "newSurname"
	newMobile := "newMobile"
	newPhone := "newPhone"
	newRemarks := "newRemarks"
	newModifiedBy := UserId(0)

	now := time.Now().UTC()

	notFoundUser := AuthUser{
		UserId:          notFoundUserId,
		Email:           newEmail,
		Username:        newUsername,
		Firstname:       newName,
		Lastname:        newSurname,
		Mobilenumber:    newMobile,
		Telephonenumber: newPhone,
		Remarks:         newRemarks,
		Modified:        now,
		ModifiedBy:      newModifiedBy,
		Type:            UserTypeLDAP,
	}
	if err := c.UpdateIdentity(&notFoundUser); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestUpdateIdentity failed: Expected ErrIdentityAuthNotFound, but got: %v", err)
	}

	joeUser := AuthUser{
		UserId:          joeUserId,
		Email:           newEmail,
		Username:        newUsername,
		Firstname:       newName,
		Lastname:        newSurname,
		Mobilenumber:    newMobile,
		Telephonenumber: newPhone,
		Remarks:         newRemarks,
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeLDAP,
	}
	if err := c.UpdateIdentity(&joeUser); err != nil {
		t.Fatalf("Update should not have failed: %v", err)
	}

	users, err := c.GetAuthenticatorIdentities(GetIdentitiesFlagNone)
	if err != nil {
		t.Fatalf("TestUpdateIdentity failed: %v", err)
	}

	updateSuccess := false
	for _, user := range users {
		if user.UserId == joeUserId && CanonicalizeIdentity(user.Email) == CanonicalizeIdentity(newEmail) && user.Username == newUsername && user.Firstname == newName && user.Lastname == newSurname && user.Mobilenumber == newMobile && user.Type == UserTypeLDAP {
			updateSuccess = true
			break
		}
	}
	if !updateSuccess {
		t.Fatalf("TestUpdateIdentity failed: After update, failed to find updated user")
	}
}

// We have to make use of the isBackendPostgresTest flag to prevent this from running for
// dummy userstore implementations, which are essentially just mimmicing the implementation
func TestAuthUpdateDuplicateIdentity(t *testing.T) {
	c := setup(t)
	defer Teardown(c)

	if isBackendPostgresTest() {
		newUsername := "newUsername"
		newName := "newName"
		newSurname := "newSurname"
		newMobile := "newMobile"
		newPhone := "newPhone"
		newRemarks := "newRemarks"
		newModifiedBy := UserId(0)

		now := time.Now().UTC()

		user, err := c.GetUserFromIdentity(joeEmail)
		if err != nil {
			t.Fatal("Couldn't find setup user")
		}
		userid := user.UserId
		jackUser := AuthUser{
			UserId:          userid,
			Email:           jackEmail,
			Username:        newUsername,
			Firstname:       newName,
			Lastname:        newSurname,
			Mobilenumber:    newMobile,
			Telephonenumber: newPhone,
			Remarks:         newRemarks,
			Modified:        now,
			ModifiedBy:      newModifiedBy,
			Type:            UserTypeDefault,
		}
		err = c.UpdateIdentity(&jackUser)

		if err != ErrIdentityExists {
			t.Fatalf("TestAuthupdateDuplicateIdentity failed: Expected ErrIdentityExists, but got: %v", err)
		}
	}
}

func TestAuthArchiveIdentity(t *testing.T) {
	c := setup(t)
	defer Teardown(c)

	now := time.Now().UTC()

	if err := c.ArchiveIdentity(notFoundUserId); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestArchiveIdentity failed: Expected ErrIdentityAuthNotFound, but got: %v", err)
	}

	if err := c.ArchiveIdentity(joeUserId); err != nil {
		t.Fatalf("Archive should not have failed: %v", err)
	}

	users, e := c.GetAuthenticatorIdentities(GetIdentitiesFlagNone)
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
		t.Fatalf("TestArchiveIdentity failed, archived user should not be found with a get none deleted flag")
	}

	archivedUsers, e := c.GetAuthenticatorIdentities(GetIdentitiesFlagDeleted)
	if e != nil {
		t.Fatalf("TestArchiveIdentity failed: %v", e)
	}

	getArchiveSuccess := false
	for _, archivedUser := range archivedUsers {
		if archivedUser.UserId == joeUserId {
			getArchiveSuccess = true
			break
		}
	}
	if !getArchiveSuccess {
		t.Fatalf("TestArchiveIdentity failed, archived user should be found with a get deleted flag")
	}

	// Using an ldap backend, authentication will succeed, as we cannot archive users on the ldap system.
	if !*backend_ldap {
		// Try to authenticate with archived user
		if _, err := c.GetTokenFromIdentityPassword(joeEmail, joePwd); err != ErrIdentityAuthNotFound {
			t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to authenticate: %v", err)
		}
	}

	// Try to update archived user
	joeUser := AuthUser{
		UserId:          joeUserId,
		Email:           "newEmail",
		Username:        "newUsername",
		Firstname:       "newName",
		Lastname:        "newSurname",
		Mobilenumber:    "newMobile",
		Telephonenumber: "newPhone",
		Remarks:         "newRemarks",
		Modified:        now,
		ModifiedBy:      0,
		Type:            UserTypeDefault,
	}
	if err := c.UpdateIdentity(&joeUser); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be updated: %v", err)
	}

	// Try resetting password of archived user
	if _, err := c.ResetPasswordStart(joeUserId, time.Now()); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be reset password: %v", err)
	}

	// Try renaming email of archived user
	if err := c.RenameIdentity(joeEmail, "newJoe"); err != ErrIdentityAuthNotFound {
		t.Fatalf("TestArchiveIdentity failed, archived user should not be allowed to be rename identity: %v", err)
	}
}
