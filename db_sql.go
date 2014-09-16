package authaus

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/lib/pq" // Tested against 04c77ed03f9b391050bec3b5f2f708f204df48b2 (Sep 16, 2014)
	"strings"
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
	row := x.db.QueryRow(`SELECT password FROM authuser WHERE LOWER(identity) = $1`, CanonicalizeIdentity(identity))
	dbHash := ""
	if err := row.Scan(&dbHash); err != nil {
		return ErrIdentityAuthNotFound
	} else {
		if verifyAuthausHash(password, dbHash) {
			return nil
		} else {
			return ErrInvalidPassword
		}
	}
}

func (x *sqlAuthenticationDB) SetPassword(identity, password string) error {
	hash, err := computeAuthausHash(password)
	if err != nil {
		return err
	}
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuser SET password = $1 WHERE LOWER(identity) = $2`, hash, CanonicalizeIdentity(identity)); eupdate == nil {
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

func (x *sqlAuthenticationDB) CreateIdentity(identity, password string) error {
	hash, ehash := computeAuthausHash(password)
	if ehash != nil {
		return ehash
	}

	if tx, etx := x.db.Begin(); etx == nil {
		if _, ecreate := tx.Exec(`INSERT INTO authuser (identity, password) VALUES ($1, $2)`, identity, hash); ecreate == nil {
			return tx.Commit()
		} else {
			//fmt.Printf("CreateIdentity failed because: %v", ecreate)
			if strings.Index(ecreate.Error(), "duplicate key") != -1 {
				ecreate = ErrIdentityExists
			}
			tx.Rollback()
			return ecreate
		}
	} else {
		return etx
	}
}

func (x *sqlAuthenticationDB) GetIdentities() ([]string, error) {
	rows, err := x.db.Query(`SELECT identity FROM authuser`)
	if err != nil {
		return []string{}, err
	}
	result := make([]string, 0)
	for rows.Next() {
		identity := ""
		if err := rows.Scan(&identity); err != nil {
			return []string{}, err
		}
		result = append(result, identity)
	}
	if rows.Err() != nil {
		return []string{}, rows.Err()
	}
	return result, nil
}

func (x *sqlAuthenticationDB) Close() {
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
	_, err := x.db.Exec(`INSERT INTO authsession (sessionkey, identity, permit, expires) VALUES($1, $2, $3, $4)`, sessionkey, CanonicalizeIdentity(token.Identity), token.Permit.Serialize(), token.Expires)
	return err
}

func (x *sqlSessionDB) Read(sessionkey string) (*Token, error) {
	x.purgeExpiredSessions()
	row := x.db.QueryRow(`SELECT identity, permit, expires FROM authsession WHERE sessionkey = $1`, sessionkey)
	token := &Token{}
	epermit := ""
	if err := row.Scan(&token.Identity, &epermit, &token.Expires); err != nil {
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

func (x *sqlSessionDB) PermitChanged(identity string, permit *Permit) error {
	_, err := x.db.Exec(`UPDATE authsession SET permit = $1 WHERE LOWER(identity) = $2`, permit.Serialize(), CanonicalizeIdentity(identity))
	return err
}

func (x *sqlSessionDB) InvalidateSessionsForIdentity(identity string) error {
	_, err := x.db.Exec(`DELETE FROM authsession WHERE LOWER(identity) = $1`, CanonicalizeIdentity(identity))
	return err
}

func (x *sqlSessionDB) Close() {
	if x.db != nil {
		x.db.Close()
	}
}

func (x *sqlSessionDB) purgeExpiredSessions() {
	x.db.Exec(`DELETE FROM authsession WHERE expires < current_timestamp`)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlPermitDB struct {
	db *sql.DB
}

func (x *sqlPermitDB) GetPermit(identity string) (*Permit, error) {
	return getPermitFromDB(x.db, "authuser", "permit", "identity", identity, ErrIdentityPermitNotFound)
}

func (x *sqlPermitDB) GetPermits() (map[string]*Permit, error) {
	return getPermitsFromDB(x.db, "authuser", "permit", "identity")
}

func (x *sqlPermitDB) SetPermit(identity string, permit *Permit) error {
	encodedPermit := permit.Serialize()
	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuser SET permit = $1 WHERE LOWER(identity) = $2`, encodedPermit, CanonicalizeIdentity(identity)); eupdate == nil {
			if affected, _ := update.RowsAffected(); affected == 1 {
				return tx.Commit()
			} else {
				if _, ecreate := tx.Exec(`INSERT INTO authuser (identity, permit) VALUES ($1, $2)`, identity, encodedPermit); ecreate == nil {
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

func (x *sqlPermitDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func getPermitFromDB(db *sql.DB, tableName, permitField, findOnField, findValue string, baseError error) (*Permit, error) {
	qstr := fmt.Sprintf(`SELECT %v FROM %v WHERE LOWER(%v) = $1`, permitField, tableName, findOnField)
	row := db.QueryRow(qstr, CanonicalizeIdentity(findValue))
	epermit := ""
	if err := row.Scan(&epermit); err != nil {
		// The following check, which according to the db/sql docs should work, fails on Postgres.
		// Suspect a bug in the Postgres driver. BMH 2014-09-12
		if err == sql.ErrNoRows {
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

func getPermitsFromDB(db *sql.DB, tableName, permitField, identityField string) (map[string]*Permit, error) {
	permits := make(map[string]*Permit)
	qstr := fmt.Sprintf(`SELECT %v, %v FROM %v`, identityField, permitField, tableName)
	rows, err := db.Query(qstr)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var identity sql.NullString
		var permit sql.NullString
		err = rows.Scan(&identity, &permit)
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
		if identity.Valid {
			permits[CanonicalizeIdentity(identity.String)] = p
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

func MigrateSchema(conx *DBConnection, schema_name string, migrations []string) error {
	return migrateSchemaInternal(true, conx, schema_name, migrations)
}

func migrateSchemaInternal(tryCreatingDB bool, conx *DBConnection, schema_name string, migrations []string) (migrateError error) {
	if db, eConnect := conx.Connect(); eConnect != nil {
		return eConnect
	} else {
		defer db.Close()

		if tx, eTxBegin := db.Begin(); eTxBegin == nil {
			defer func() {
				if err := recover(); err == nil {
					migrateError = tx.Commit()
				} else {
					tx.Rollback()
					migrateError = err.(error)
				}
			}()

			version, eGetVersion := readSchemaVersion(tx, schema_name)
			if eGetVersion != nil {
				panic(eGetVersion)
			}

			if version > len(migrations) {
				panic(errors.New(fmt.Sprintf("%v database is newer than this program (%v)", schema_name, version)))
			}

			for ; version < len(migrations); version += 1 {
				fmt.Printf("Migrating %v to version %v\n", schema_name, version+1)
				if _, err := tx.Exec(migrations[version]); err != nil {
					panic(err)
				}
				if _, err := tx.Exec(fmt.Sprintf("UPDATE %v_version SET version = %v", schema_name, version+1)); err != nil {
					panic(err)
				}
			}
			return nil
		} else {
			// Match the string 'database "foo" does not exist' to detect when the database needs to be created
			if tryCreatingDB && strings.Index(eTxBegin.Error(), "does not exist") != -1 {
				if eCreateDB := SqlCreateDatabase(conx); eCreateDB != nil {
					return eCreateDB
				} else {
					return migrateSchemaInternal(false, conx, schema_name, migrations)
				}
			} else {
				return eTxBegin
			}
		}
	}
}

// Create a Postgres DB schema necessary for a Session database
func SqlCreateSchema_Session(conx *DBConnection) error {
	versions := make([]string, 0)
	versions = append(versions, `
	CREATE TABLE authsession (id BIGSERIAL PRIMARY KEY, sessionkey VARCHAR, identity VARCHAR, permit VARCHAR, expires TIMESTAMP);
	CREATE UNIQUE INDEX idx_authsession_token    ON authsession (sessionkey);
	CREATE        INDEX idx_authsession_identity ON authsession (identity);
	CREATE        INDEX idx_authsession_expires  ON authsession (expires);`)

	return MigrateSchema(conx, "authsession", versions)
}

// Create a Postgres DB schema suitable for storage of Permits and Authentication
// Note that we COULD separate Permit and Authenticator, but I'm not sure that provides any value.
// It would be trivial to do so if that need ever arises.
func SqlCreateSchema_User(conx *DBConnection) error {
	versions := make([]string, 0)
	versions = append(versions, `
	CREATE TABLE authuser (id BIGSERIAL PRIMARY KEY, identity VARCHAR, password VARCHAR, permit VARCHAR);
	CREATE UNIQUE INDEX idx_authuser_identity ON authuser (identity);`)

	versions = append(versions, `
	DROP INDEX idx_authuser_identity;
	CREATE UNIQUE INDEX idx_authuser_identity ON authuser (LOWER(identity));`)

	return MigrateSchema(conx, "authuser", versions)
}
