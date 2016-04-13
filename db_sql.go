package authaus

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	//"errors"
	"fmt"
	"github.com/BurntSushi/migration"
	_ "github.com/lib/pq" // Tested against 04c77ed03f9b391050bec3b5f2f708f204df48b2 (Sep 16, 2014)
	"golang.org/x/crypto/scrypt"
	"strconv"
	"strings"
	"time"
)

/*
Hash encodings:

Version 1:
65 bytes (1 + 32 + 32).
bytes[0]     = 1
bytes[1:33]  = Salt (32 random bytes)
bytes[33:65] = scrypt-ed hash with parameters N=256 r=8 p=1

Why use such a low parameter (N=256) for scrypt?
This is a balance between server cost and password crackability.
If you decide that you need to raise the N factor, then introduce a new
version of the hash (the only version right now is version 1).

scrypt(256) on a first generation Intel i7 (i920, circa 2009) takes
approximately 1 millisecond to compute.

*/

const (
	hashLengthV1 = 65
	scryptN_V1   = 256
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlAuthenticationDB struct {
	db *sql.DB
}

func (x *sqlAuthenticationDB) Authenticate(identity, password string) error {
	row := x.db.QueryRow(`SELECT userid FROM authuserstore WHERE LOWER(email) = $1 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(identity))
	var userId int64
	if err := row.Scan(&userId); err != nil {
		return ErrIdentityAuthNotFound
	}

	row = x.db.QueryRow(`SELECT password FROM authuserpwd WHERE userid = $1`, userId)
	dbHash := ""
	if err := row.Scan(&dbHash); err != nil {
		return ErrIdentityAuthNotFound
	}

	if verifyAuthausHash(password, dbHash) {
		return nil
	} else {
		return ErrInvalidPassword
	}
}

func (x *sqlAuthenticationDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

type sqlUserStoreDB struct {
	db *sql.DB
}

func (x *sqlUserStoreDB) SetPassword(userId UserId, password string) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if eupdate := x.setPasswordInternal(tx, userId, password); eupdate == nil {
			return tx.Commit()
		} else {
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) setPasswordInternal(tx *sql.Tx, userId UserId, password string) error {
	hash, err := computeAuthausHash(password)
	if err != nil {
		return err
	}

	if update, eupdate := tx.Exec(`UPDATE authuserpwd SET password = $1, pwdtoken = NULL WHERE userid = $2`, hash, userId); eupdate == nil {
		if affected, _ := update.RowsAffected(); affected == 1 {
			return nil
		} else {
			return ErrIdentityAuthNotFound
		}
	} else {
		return eupdate
	}
}

func (x *sqlUserStoreDB) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	if tx, etx := x.db.Begin(); etx == nil {
		token := generatePasswordResetToken(expires)
		if update, eupdate := tx.Exec(`UPDATE authuserpwd AS aup SET pwdtoken = $1 FROM authuserstore AS aus WHERE aus.userid = aup.userid AND aup.userid = $2 AND (aus.archived = false OR aus.archived IS NULL)`, token, userId); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return token, tx.Commit()
			} else {
				tx.Rollback()
				return "", ErrIdentityAuthNotFound
			}
		} else {
			return "", eupdate
		}
	} else {
		return "", etx
	}
}

func (x *sqlUserStoreDB) ResetPasswordFinish(userId UserId, token string, password string) error {
	if tx, etx := x.db.Begin(); etx == nil {
		var truthToken sql.NullString
		if escan := tx.QueryRow("SELECT pwdtoken FROM authuserpwd WHERE userid = $1", userId).Scan(&truthToken); escan != nil {
			tx.Rollback()
			if escan == sql.ErrNoRows {
				return ErrIdentityAuthNotFound
			}
			return escan
		}
		if everify := verifyPasswordResetToken(token, truthToken.String); everify != nil {
			tx.Rollback()
			return everify
		}
		if eupdate := x.setPasswordInternal(tx, userId, password); eupdate != nil {
			tx.Rollback()
			return eupdate
		} else {
			return tx.Commit()
		}

	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) CreateIdentity(email, username, firstname, lastname, mobilenumber, password string) (UserId, error) {
	hash, ehash := computeAuthausHash(password)
	if ehash != nil {
		return NullUserId, ehash
	}

	// Insert into user store
	if tx, etx := x.db.Begin(); etx == nil {
		if _, eCreateUserStore := tx.Exec(`INSERT INTO authuserstore (email, username, firstname, lastname, mobile, archived) VALUES ($1, $2, $3, $4, $5, $6)`, email, username, firstname, lastname, mobilenumber, false); eCreateUserStore != nil {
			//fmt.Printf("CreateIdentity failed because: %v", ecreate)
			if strings.Index(eCreateUserStore.Error(), "duplicate key") != -1 {
				eCreateUserStore = ErrIdentityExists
			}
			tx.Rollback()
			return NullUserId, eCreateUserStore
		}

		// Get user id
		var userId int64
		row := tx.QueryRow(`SELECT userid FROM authuserstore WHERE email = $1`, email)
		if scanErr := row.Scan(&userId); scanErr != nil {
			tx.Rollback()
			return NullUserId, scanErr
		}

		// Insert into auth user
		if _, eCreateAuthUser := tx.Exec(`INSERT INTO authuserpwd (userid, password) VALUES ($1, $2)`, userId, hash); eCreateAuthUser != nil {
			if strings.Index(eCreateAuthUser.Error(), "duplicate key") != -1 {
				eCreateAuthUser = ErrIdentityExists
			}
			tx.Rollback()
			return NullUserId, eCreateAuthUser
		}

		return UserId(userId), tx.Commit()
	} else {
		return NullUserId, etx
	}
}

func (x *sqlUserStoreDB) UpdateIdentity(userId UserId, email, username, firstname, lastname, mobilenumber string) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserstore SET email = $1, username = $2, firstname = $3, lastname = $4, mobile = $5 WHERE userid = $6 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(email), username, firstname, lastname, mobilenumber, userId); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				tx.Rollback()
				return ErrIdentityAuthNotFound
			}
		} else {
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) ArchiveIdentity(userId UserId) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserstore SET archived = $1 WHERE userid = $2`, true, userId); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				tx.Rollback()
				return ErrIdentityAuthNotFound
			}
		} else {
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) RenameIdentity(oldIdent, newIdent string) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserstore SET email = $1 WHERE LOWER(email) = $2`, newIdent, CanonicalizeIdentity(oldIdent)); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				tx.Rollback()
				return ErrIdentityAuthNotFound
			}
		} else {
			if strings.Index(eupdate.Error(), "duplicate key") != -1 {
				eupdate = ErrIdentityExists
			}
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) GetIdentities() ([]AuthUser, error) {
	rows, err := x.db.Query(`SELECT userid, email, username, firstname, lastname, mobile FROM authuserstore WHERE (archived = false OR archived IS NULL) ORDER BY email`)
	if err != nil {
		return []AuthUser{}, err
	}
	defer rows.Close()
	result := make([]AuthUser, 0)
	type sqlUser struct {
		userid       sql.NullInt64
		email        sql.NullString
		username     sql.NullString
		firstname    sql.NullString
		lastname     sql.NullString
		mobilenumber sql.NullString
	}
	for rows.Next() {
		user := sqlUser{}
		if err := rows.Scan(&user.userid, &user.email, &user.username, &user.firstname, &user.lastname, &user.mobilenumber); err != nil {
			return []AuthUser{}, err
		}
		result = append(result, AuthUser{UserId(user.userid.Int64), user.email.String, user.username.String, user.firstname.String, user.lastname.String, user.mobilenumber.String})
	}
	if rows.Err() != nil {
		return []AuthUser{}, rows.Err()
	}
	return result, nil
}

func (x *sqlUserStoreDB) GetIdentityFromUserId(userId UserId) (string, error) {
	row := x.db.QueryRow(`SELECT email FROM authuserstore WHERE userid = $1 AND (archived = false OR archived IS NULL)`, userId)
	var identity string
	if scanErr := row.Scan(&identity); scanErr != nil {
		return "", scanErr
	}
	return identity, nil
}

func (x *sqlUserStoreDB) GetUserIdFromIdentity(identity string) (UserId, error) {
	row := x.db.QueryRow(`SELECT userid FROM authuserstore WHERE email = $1 AND (archived = false OR archived IS NULL)`, identity)
	var userId int64
	if scanErr := row.Scan(&userId); scanErr != nil {
		return 0, scanErr
	}
	return UserId(userId), nil
}

func (x *sqlUserStoreDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlSessionDB struct {
	db *sql.DB
}

func (x *sqlSessionDB) Write(sessionkey string, token *Token) error {
	_, err := x.db.Exec(`INSERT INTO authsession (sessionkey, userid, permit, expires) VALUES($1, $2, $3, $4)`, sessionkey, token.UserId, token.Permit.Serialize(), token.Expires)
	return err
}

func (x *sqlSessionDB) Read(sessionkey string) (*Token, error) {
	x.purgeExpiredSessions()
	row := x.db.QueryRow(`SELECT identity, permit, expires FROM authsession WHERE sessionkey = $1`, sessionkey)
	token := &Token{}
	epermit := ""
	if err := row.Scan(&token.UserId, &epermit, &token.Expires); err != nil {
		return nil, ErrInvalidSessionToken
	} else {
		if err := token.Permit.Deserialize(epermit); err != nil {
			return nil, ErrInvalidSessionToken
		} else {
			return token, nil
		}
	}
}

func (x *sqlSessionDB) Delete(sessionkey string) error {
	_, err := x.db.Exec(`DELETE FROM authsession WHERE sessionkey = $1`, sessionkey)
	return err
}

func (x *sqlSessionDB) PermitChanged(userId UserId, permit *Permit) error {
	_, err := x.db.Exec(`UPDATE authsession SET permit = $1 WHERE userid = $2`, permit.Serialize(), userId)
	return err
}

func (x *sqlSessionDB) InvalidateSessionsForIdentity(userId UserId) error {
	_, err := x.db.Exec(`DELETE FROM authsession WHERE userid = $1`, userId)
	return err
}

func (x *sqlSessionDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

func (x *sqlSessionDB) purgeExpiredSessions() {
	x.db.Exec(`DELETE FROM authsession WHERE expires < current_timestamp`)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlPermitDB struct {
	db *sql.DB
}

func (x *sqlPermitDB) GetPermit(userId UserId) (*Permit, error) {
	return getPermitFromDB(x.db, "authuserpwd", "permit", "userid", userId, ErrIdentityPermitNotFound)
}

func (x *sqlPermitDB) GetPermits() (map[UserId]*Permit, error) {
	return getPermitsFromDB(x.db, "authuserpwd", "permit", "userid")
}

func (x *sqlPermitDB) SetPermit(userId UserId, permit *Permit) error {
	encodedPermit := permit.Serialize()
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserpwd SET permit = $1 WHERE userid = $2`, encodedPermit, userId); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				if _, ecreate := tx.Exec(`INSERT INTO authuserpwd (userid, permit) VALUES ($1, $2)`, userId, encodedPermit); ecreate == nil {
					return tx.Commit()
				} else {
					tx.Rollback()
					return ecreate
				}
			}
		} else {
			tx.Rollback()
			return eupdate
		}
	} else {
		return etx
	}
}

func (x *sqlPermitDB) RenameIdentity(oldIdent, newIdent string) error {
	// In this design, we store Authenticator and PermitDB in the same table, so we let the Authenticator portion
	// handle the rename. Once that's done, we have no work left to do here.
	return nil
}

func (x *sqlPermitDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func getPermitFromDB(db *sql.DB, tableName, permitField, findOnField string, userId UserId, baseError error) (*Permit, error) {
	qstr := fmt.Sprintf(`SELECT %v FROM %v WHERE %v = $1`, permitField, tableName, findOnField)
	row := db.QueryRow(qstr, userId)
	epermit := ""
	if err := row.Scan(&epermit); err != nil {
		// The following check, which according to the db/sql docs should work, fails on Postgres.
		// Suspect a bug in the Postgres driver. BMH 2014-09-12
		if err == sql.ErrNoRows {
			return nil, baseError
		}
		// Work around for the bug mentioned above (2014-10-07)
		if strings.Index(err.Error(), "Scan error on column index 0") != -1 {
			return nil, baseError
		}
		return nil, NewError(baseError, err.Error())
	} else {
		p := &Permit{}
		if err := p.Deserialize(epermit); err != nil {
			return nil, NewError(baseError, err.Error())
		} else {
			return p, nil
		}
	}
}

func getPermitsFromDB(db *sql.DB, tableName, permitField, userIdField string) (map[UserId]*Permit, error) {
	permits := make(map[UserId]*Permit)
	qstr := fmt.Sprintf(`SELECT %v, %v FROM %v`, userIdField, permitField, tableName)
	rows, err := db.Query(qstr)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var strUserId sql.NullString
		var permit sql.NullString
		err = rows.Scan(&strUserId, &permit)
		if err != nil {
			return nil, err
		}
		p := &Permit{}
		if permit.Valid {
			err = p.Deserialize(permit.String)
		}
		if err != nil {
			return nil, err
		}
		if strUserId.Valid {
			if userId, err := strconv.ParseInt(strUserId.String, 10, 64); err == nil {
				permits[UserId(userId)] = p
			} else {
				return nil, err
			}
		}
	}
	return permits, err
}

func verifyAuthausHash(password, hash string) bool {
	block, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	if len(block) == hashLengthV1 {
		if block[0] != 1 {
			return false
		}
		scrypted, err := scrypt.Key([]byte(password), block[1:33], scryptN_V1, 8, 1, 32)
		if err != nil {
			return false
		}
		return subtle.ConstantTimeCompare(block[33:], scrypted) == 1
	} else {
		return false
	}
}

func computeAuthausHash(password string) (string, error) {
	cblock := [hashLengthV1]byte{}
	cblock[0] = 1
	if ncrypto, err := rand.Read(cblock[1:33]); ncrypto != 32 || err != nil {
		return "", err
	}
	scrypted, err := scrypt.Key([]byte(password), cblock[1:33], scryptN_V1, 8, 1, 32)
	if err != nil {
		return "", err
	}
	copy(cblock[33:], scrypted)
	return base64.StdEncoding.EncodeToString(cblock[:]), nil
}

func NewAuthenticationDB_SQL(conx *DBConnection) (Authenticator, error) {
	db := new(sqlAuthenticationDB)
	var err error
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

func NewUserStoreDB_SQL(conx *DBConnection) (UserStore, error) {
	db := new(sqlUserStoreDB)
	var err error
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

func NewSessionDB_SQL(conx *DBConnection) (SessionDB, error) {
	db := new(sqlSessionDB)
	var err error
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

func NewPermitDB_SQL(conx *DBConnection) (PermitDB, error) {
	db := new(sqlPermitDB)
	var err error
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

// schema_name must be a lower case SQL table name that needs no escaping
// Returns (0,nil) if this is the first time we have seen this database
func readSchemaVersion(tx *sql.Tx, schema_name string) (int, error) {
	tableName := schema_name + "_version"
	if _, err := tx.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (version INTEGER)", tableName)); err != nil {
		return 0, err
	}
	query := tx.QueryRow(fmt.Sprintf("SELECT version FROM %v", tableName))
	var version int = 0
	if err := query.Scan(&version); err != nil {
		if err == sql.ErrNoRows {
			if _, err := tx.Exec(fmt.Sprintf("INSERT INTO %v (version) VALUES (0)", tableName)); err != nil {
				return 0, err
			}
			return version, nil
		}
		return 0, err

	} else {
		return version, nil
	}
}

func SqlCreateDatabase(conx *DBConnection) error {
	// Check first if the database already exists
	if db, eConnect := conx.Connect(); eConnect == nil {
		// The postgres driver will not return an error until we attempt to start a transaction
		if tx, eTxBegin := db.Begin(); eTxBegin == nil {
			tx.Rollback()
			db.Close()
			return nil
		} else {
			// database does not exist, go ahead and try to create it
			db.Close()
		}
	} else {
		return eConnect
	}
	// Connect via the 'postgres' database
	copy := *conx
	copy.Database = "postgres"
	if db, e := copy.Connect(); e == nil {
		defer db.Close()
		_, eExec := db.Exec("CREATE DATABASE \"" + conx.Database + "\"")
		return eExec
	} else {
		return e
	}
}

func RunMigrations(conx *DBConnection) (bool, error) {
	// Until March 2016, Authaus used it's own migration tool, but we moved away from that and started using a migration tool by BurntSushi.
	// This requires us to delete old version tracking tables etc. However, we would like to make sure we have run all the migrations, with the old migration tool, as migration version
	// storage between tools work differently. Once we are positive that the old migrations that run with the old migration tool
	// are run, we can proceed with the following:
	// We need to delete old version tracking tables used by the old migration tool. We need to set the correct migration version number we
	// are currently on in the new migration version tracking table, as we are keeping our previous migration scripts for obvious maintenance reasons
	// and for running on brand new systems.
	err := runBootstrap(conx)
	if err != nil {
		return false, err
	}

	conStr := fmt.Sprintf("host=%v user=%v password=%v dbname=%v sslmode=disable", conx.Host, conx.User, conx.Password, conx.Database)
	_, err = migration.Open(conx.Driver, conStr, createMigrations())
	if err != nil {
		return false, err
	}
	return true, err

	return false, nil
}

func createVersionTable(db *sql.DB, version int) error {
	_, err := db.Exec(fmt.Sprintf(`
		CREATE TABLE migration_version (
			version INTEGER
		);
		INSERT INTO migration_version (version) VALUES (%v)`, version))
	return err
}

func createMigrations() []migration.Migrator {
	var migrations []migration.Migrator

	text := []string{
		// authgroup migrations
		`CREATE TABLE authgroup (id SERIAL PRIMARY KEY, name VARCHAR, permlist VARCHAR);
		CREATE UNIQUE INDEX idx_authgroup_name ON authgroup (name);`,

		// authsession migrations
		`CREATE TABLE authsession (id BIGSERIAL PRIMARY KEY, sessionkey VARCHAR, identity VARCHAR, permit VARCHAR, expires TIMESTAMP);
		CREATE UNIQUE INDEX idx_authsession_token ON authsession (sessionkey);
		CREATE INDEX idx_authsession_identity ON authsession (identity);
		CREATE INDEX idx_authsession_expires  ON authsession (expires);`,

		`DELETE FROM authsession;`,

		// authuser migrations
		`CREATE TABLE authuser (id BIGSERIAL PRIMARY KEY, identity VARCHAR, password VARCHAR, permit VARCHAR);
		CREATE UNIQUE INDEX idx_authuser_identity ON authuser (identity);`,

		`DROP INDEX idx_authuser_identity;
		CREATE UNIQUE INDEX idx_authuser_identity ON authuser (LOWER(identity));`,

		`ALTER TABLE authuser ADD COLUMN pwdtoken VARCHAR;`,

		// Change from using email address as the primary identity of a user, to a 64-bit integer, which we call UserId.
		// The above migrations were from the old migration system, from this migration on we are using the new migration
		// system from BurntSushi
		`CREATE TABLE authuserstore (userid BIGSERIAL PRIMARY KEY, email VARCHAR, username VARCHAR, firstname VARCHAR, lastname VARCHAR, mobile VARCHAR, archived BOOLEAN);
		CREATE UNIQUE INDEX idx_authuserstore_email ON authuserstore (LOWER(email));
		INSERT INTO authuserstore (email) SELECT identity from authuser;

		CREATE TABLE authsession_temp(id BIGSERIAL PRIMARY KEY, sessionkey VARCHAR, identity VARCHAR, permit VARCHAR, expires TIMESTAMP);
		INSERT INTO authsession_temp (id, sessionkey, identity, permit, expires) SELECT * FROM authsession;
		DROP TABLE IF EXISTS authsession;
		CREATE TABLE authsession(id BIGSERIAL PRIMARY KEY, sessionkey VARCHAR, userid BIGSERIAL, permit VARCHAR, expires TIMESTAMP);
		CREATE UNIQUE INDEX idx_authsession_token ON authsession (sessionkey);
		CREATE INDEX idx_authsession_expires  ON authsession (expires);
		CREATE INDEX idx_authsession_userid ON authsession (userid);
		INSERT INTO authsession (id, sessionkey, userid, permit, expires)
		SELECT authtemp.id, authtemp.sessionkey, us.userid, authtemp.permit, authtemp.expires FROM authsession_temp AS authtemp
		JOIN authuserstore AS us ON us.email = authtemp.identity;
		DROP TABLE authsession_temp;

		CREATE TABLE authuser_temp(id BIGSERIAL PRIMARY KEY, identity VARCHAR, password VARCHAR, permit VARCHAR, pwdtoken VARCHAR);
		INSERT INTO authuser_temp (id, identity, password, permit, pwdtoken) SELECT * FROM authuser;
		DROP TABLE IF EXISTS authuser;
		CREATE TABLE authuserpwd(id BIGSERIAL PRIMARY KEY, userid BIGSERIAL, password VARCHAR, permit VARCHAR, pwdtoken VARCHAR);
		INSERT INTO authuserpwd (id, userid, password, permit, pwdtoken)
		SELECT usertemp.id, us.userid, usertemp.password, usertemp.permit, usertemp.pwdtoken FROM authuser_temp AS usertemp
		JOIN authuserstore AS us ON us.email = usertemp.identity;
		DROP TABLE authuser_temp;`,
	}

	for _, src := range text {
		srcCapture := src
		migrations = append(migrations, func(tx migration.LimitedTx) error {
			_, err := tx.Exec(srcCapture)
			return err
		})
	}
	return migrations
}

// This function makes sure that the old migrations that were part of the old migration tool have run, returns true on success else false with error
func runBootstrap(conx *DBConnection) error {
	db, eConnect := conx.Connect()
	if eConnect != nil {
		return ErrConnect
	}

	oldVersionTables := []string{"authgroup_version", "authsession_version", "authuser_version"}
	// We first want to see if the new migrator has taken over, by checking if old version tracking tables exist
	tableNameResult := ""
	query := db.QueryRow(fmt.Sprintf("SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '%v'", oldVersionTables[0]))
	err := query.Scan(&tableNameResult)
	if err != nil {
		if strings.Index(err.Error(), "no rows in result set") != -1 {
			// Tracking tables dont exist, this is up to date
			return nil
		}
		return err
	}

	getTableVersion := func(table string) (int, error) {
		var version int
		row := db.QueryRow(fmt.Sprintf("SELECT version FROM %v", table))
		err := row.Scan(&version)
		if err != nil {
			return -1, err
		} else {
			return version, nil
		}
	}

	version1, err1 := getTableVersion(oldVersionTables[0])
	if err1 != nil {
		return err1
	}
	version2, err2 := getTableVersion(oldVersionTables[1])
	if err2 != nil {
		return err2
	}
	version3, err3 := getTableVersion(oldVersionTables[2])
	if err3 != nil {
		return err3
	}

	// version1 is the version of authgroup_version, which must be equal to 1
	// version2 is the version of authsession_version, which must be equal to 2
	// version3 is the version of authuser_version, which must be equal to 3
	if version1 == 1 && version2 == 2 && version3 == 3 {
		// Tracking tables do exist, we need to remove them
		for _, oldVersionTable := range oldVersionTables {
			_, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %v", oldVersionTable))
			if err != nil {
				return err
			}
		}
	}

	// We need to set the version in new migration version tracking table
	// We need to keep track of migration version, moving from old to new migration tool
	createVersionTable(db, 6)

	return nil
}
