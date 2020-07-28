package authaus

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/BurntSushi/migration"
	// Tested against 04c77ed03f9b391050bec3b5f2f708f204df48b2 (Sep 16, 2014)
)

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

func RunMigrations(conx *DBConnection) error {
	// Until March 2016, Authaus used it's own migration tool, but we now use https://github.com/BurntSushi/migration instead.
	// If the bootstrap process seems contrived, it's because it needs to cater for the upgrade from the old
	// in-house migration system, to the BurntSushi system.
	err := runBootstrap(conx)
	if err != nil {
		return err
	}

	db, err := migration.Open(conx.Driver, conx.ConnectionString(), createMigrations())

	if err == nil {
		db.Close()
	}
	return err
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
		// 1. authgroup
		`CREATE TABLE authgroup (id SERIAL PRIMARY KEY, name VARCHAR, permlist VARCHAR);
		CREATE UNIQUE INDEX idx_authgroup_name ON authgroup (name);`,

		// 2. authsession
		`CREATE TABLE authsession (id BIGSERIAL PRIMARY KEY, sessionkey VARCHAR, identity VARCHAR, permit VARCHAR, expires TIMESTAMP);
		CREATE UNIQUE INDEX idx_authsession_token ON authsession (sessionkey);
		CREATE INDEX idx_authsession_identity ON authsession (identity);
		CREATE INDEX idx_authsession_expires  ON authsession (expires);`,

		// 3.
		`DELETE FROM authsession;`,

		// 4. authuser
		`CREATE TABLE authuser (id BIGSERIAL PRIMARY KEY, identity VARCHAR, password VARCHAR, permit VARCHAR);
		CREATE UNIQUE INDEX idx_authuser_identity ON authuser (identity);`,

		// 5. authuser (case insensitive)
		`DROP INDEX idx_authuser_identity;
		CREATE UNIQUE INDEX idx_authuser_identity ON authuser (LOWER(identity));`,

		// 6. password reset
		`ALTER TABLE authuser ADD COLUMN pwdtoken VARCHAR;`,

		// END OF OLD (pre BurntSushi) MIGRATIONS

		// 7. Change from using email address as the primary identity of a user, to a 64-bit integer, which we call UserId.
		`CREATE TABLE authuserstore (userid BIGSERIAL PRIMARY KEY, email VARCHAR, username VARCHAR, firstname VARCHAR, lastname VARCHAR, mobile VARCHAR, archived BOOLEAN);
		CREATE INDEX idx_authuserstore_email ON authuserstore (LOWER(email));
		INSERT INTO authuserstore (email) SELECT identity from authuser;

		ALTER TABLE authsession ADD COLUMN userid BIGINT;
		UPDATE authsession
			SET userid = authuserstore.userid
			FROM authuserstore
			WHERE authuserstore.email = authsession.identity;
		ALTER TABLE authsession DROP COLUMN identity;

		CREATE TABLE authuserpwd(userid BIGINT PRIMARY KEY, password VARCHAR, permit VARCHAR, pwdtoken VARCHAR);
		INSERT INTO authuserpwd (userid, password, permit, pwdtoken)
			SELECT store.userid, password, permit, pwdtoken
			FROM authuser
			INNER JOIN authuserstore AS store
			ON authuser.identity = store.email;

		DROP TABLE authuser;
		`,

		// 8. We add AuthUserType field to the userstore, to determine what type of user account this is.
		`ALTER TABLE authuserstore ADD COLUMN authusertype SMALLINT default 0;`,

		// 9. Additional data fields as well as fields to keep track of changes to users
		`ALTER TABLE authuserstore
			ADD COLUMN phone VARCHAR,
			ADD COLUMN remarks VARCHAR,
			ADD COLUMN created TIMESTAMP,
			ADD COLUMN createdby BIGINT,
			ADD COLUMN modified TIMESTAMP,
			ADD COLUMN modifiedby BIGINT;`,

		// 10. Archive passwords
		`ALTER TABLE authuserstore  ALTER COLUMN modified SET DEFAULT NOW();
		ALTER TABLE authuserpwd  ADD COLUMN created TIMESTAMP DEFAULT NOW();
		ALTER TABLE authuserpwd  ADD COLUMN updated TIMESTAMP DEFAULT NOW();

		CREATE TABLE authpwdarchive (id BIGSERIAL PRIMARY KEY, userid BIGINT NOT NULL, password VARCHAR NOT NULL, created TIMESTAMP DEFAULT NOW());
		`,

		// 11. Account lock
		`ALTER TABLE authuserpwd ADD COLUMN accountlocked BOOLEAN DEFAULT FALSE;`,

		// 12. OAuth (tables are prefixed with oauth, because authoauth is just too silly)
		//     We have no use for externaluuid yet, but it seems like a good idea to try and pin as permanent
		//     a handle onto an identity.
		`CREATE TABLE oauthchallenge (id VARCHAR PRIMARY KEY, provider VARCHAR NOT NULL, created TIMESTAMP NOT NULL, nonce VARCHAR, pkce_verifier VARCHAR);
		CREATE TABLE oauthsession (id VARCHAR PRIMARY KEY, provider VARCHAR NOT NULL, created TIMESTAMP NOT NULL, updated TIMESTAMP NOT NULL, token JSONB);
		CREATE INDEX idx_oauthchallenge_created ON oauthchallenge (created);
		CREATE INDEX idx_oauthsession_updated ON oauthsession (updated);
		ALTER TABLE authuserstore ADD COLUMN externaluuid UUID;
		ALTER TABLE authsession ADD COLUMN oauthid VARCHAR;
		`,
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

/* This moves from the old in-house migration system to BurntSushi
The system can be in one of three permissible states here:
1. Empty DB
2. Authaus DB prior to BurntSushi
3. Using BurntSushi
*/
func runBootstrap(conx *DBConnection) error {
	db, eConnect := conx.Connect()
	if eConnect != nil {
		return NewError(ErrConnect, eConnect.Error())
	}
	defer db.Close()

	var version int
	r := db.QueryRow("SELECT version FROM migration_version")
	if err := r.Scan(&version); err == nil {
		// If the table 'migration_version' exists, then we have already upgraded (ie state #3)
		return nil
	}

	// The following two arrays are parallel
	oldVersionTables := []string{"authuser_version", "authgroup_version", "authsession_version"}
	oldVersionNumbers := []int{3, 1, 2}

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

	for i := 0; i < 3; i++ {
		version, err := getTableVersion(oldVersionTables[i])
		if err != nil {
			// The old version tables do not exist. Assume this is an empty DB (ie state #1)
			if strings.Index(err.Error(), "does not exist") != -1 {
				return nil
			}
			return fmt.Errorf("Error when scanning for old Authaus migration system: %v", err)
		} else if version != oldVersionNumbers[i] {
			return fmt.Errorf("Unable to upgrade semi-old database (%v at version %v, instead of %v)", oldVersionTables[i], version, oldVersionNumbers[i])
		}
	}

	// The remainder of this function deals with state #2 (old Authaus migration system is present)

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	for _, tab := range oldVersionTables {
		_, err := db.Exec(fmt.Sprintf("DROP TABLE %v", tab))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("Error dropping old version table %v: %v", tab, err)
		}
	}

	// Under normal usage of the BurntSushi system, we wouldn't perform this step.
	// However, in our case, we are "pre-seeding" the BurntSushi system, by telling
	// it that we have already run migrations 1 through 6. The first six migrations
	// were the ones that were run as part of the old Authaus built-in migration system.
	err = createVersionTable(db, 6)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("Error bootstrapping BurntSushi migration system: %v", err)
	}
	return tx.Commit()
}
