package authaus

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/migration"
	"github.com/lib/pq" // Tested against 04c77ed03f9b391050bec3b5f2f708f204df48b2 (Sep 16, 2014)
	"golang.org/x/crypto/scrypt"
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

type sqlUserStoreDB struct {
	db             *sql.DB
	passwordExpiry time.Duration
}

func (x *sqlUserStoreDB) SetConfig(passwordExpiry time.Duration) error {
	x.passwordExpiry = passwordExpiry
	return nil
}

func (x *sqlUserStoreDB) Authenticate(identity, password string, authTypeCheck AuthCheck) error {
	row := x.db.QueryRow(`SELECT userid FROM authuserstore WHERE (LOWER(email) = $1 OR LOWER(username) = $1) AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(identity))
	var userId int64
	if err := row.Scan(&userId); err != nil {
		return ErrIdentityAuthNotFound
	}

	row = x.db.QueryRow(`SELECT password, updated, coalesce(accountlocked, false) FROM authuserpwd WHERE userid = $1`, userId)
	var dbHash sql.NullString
	var lastUpdated time.Time
	var accountLocked bool
	if err := row.Scan(&dbHash, &lastUpdated, &accountLocked); err != nil {
		return ErrIdentityAuthNotFound
	} else if accountLocked {
		return ErrAccountLocked
	}

	// The following step was added when we found some passwords being null.
	// This happens when an ldap user is "migrated" to an IMQS user as we store
	// the password for an ldap user as nil.
	pHash := ""
	if dbHash.Valid {
		pHash = dbHash.String
	}

	if !verifyAuthausHash(password, pHash) {
		return ErrInvalidPassword
	}

	if x.passwordExpiry != 0 && authTypeCheck&AuthCheckPasswordExpired != 0 {
		if lastUpdated.Add(x.passwordExpiry).Before(time.Now()) {
			return ErrPasswordExpired
		}
	}
	return nil
}

func (x *sqlUserStoreDB) SetPassword(userId UserId, password string, enforceTypeCheck PasswordEnforcement) error {
	if tx, etx := x.db.Begin(); etx == nil {
		if enforceTypeCheck&PasswordEnforcementReuse != 0 && x.hasPasswordBeenUsedBefore(userId, password) {
			tx.Rollback()
			return ErrInvalidPastPassword
		}

		if earchive := x.archivePassword(tx, userId); earchive != nil {
			tx.Rollback()
			return earchive
		}

		if eupdate := x.setPasswordInternal(tx, userId, password); eupdate != nil {
			tx.Rollback()
			return eupdate
		}
		return tx.Commit()
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) setPasswordInternal(tx *sql.Tx, userId UserId, password string) error {
	hash, err := computeAuthausHash(password)
	if err != nil {
		return err
	}

	if update, eupdate := tx.Exec(`UPDATE authuserpwd SET password = $1, pwdtoken = NULL, updated = $2 WHERE userid = $3`, hash, time.Now().UTC(), userId); eupdate == nil {
		if affected, _ := update.RowsAffected(); affected == 1 {
			return nil
		}
		return ErrIdentityAuthNotFound

	} else {
		return eupdate
	}
}

func (x *sqlUserStoreDB) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	if tx, etx := x.db.Begin(); etx == nil {
		token := generatePasswordResetToken(expires)
		if update, eupdate := tx.Exec(`UPDATE authuserpwd AS aup SET pwdtoken = $1 FROM authuserstore AS aus WHERE aus.userid = aup.userid AND aup.userid = $2 AND (aus.archived = false OR aus.archived IS NULL) AND aus.authusertype = $3`, token, userId, UserTypeDefault); eupdate == nil {
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

func (x *sqlUserStoreDB) ResetPasswordFinish(userId UserId, token string, password string, enforceTypeCheck PasswordEnforcement) error {
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

		if enforceTypeCheck&PasswordEnforcementReuse != 0 && x.hasPasswordBeenUsedBefore(userId, password) {
			tx.Rollback()
			return ErrInvalidPastPassword
		}

		if earchive := x.archivePassword(tx, userId); earchive != nil {
			tx.Rollback()
			return earchive
		}

		if eupdate := x.setPasswordInternal(tx, userId, password); eupdate != nil {
			tx.Rollback()
			return eupdate
		}
		return tx.Commit()
	} else {
		return etx
	}
}

func (x *sqlUserStoreDB) archivePassword(tx *sql.Tx, userId UserId) error {
	if _, err := tx.Exec(`INSERT INTO authpwdarchive (userid, password) SELECT userid, password FROM authuserpwd WHERE password IS NOT NULL AND  userId = $1`, userId); err != nil {
		return err
	}
	return nil
}

func (x *sqlUserStoreDB) hasPasswordBeenUsedBefore(userId UserId, password string) bool {
	recentPasswords, err := x.getRecentPasswordsForUser(userId)
	if err != nil {
		return false
	}
	for _, hash := range recentPasswords {
		if verifyAuthausHash(password, hash) {
			return true
		}
	}
	return false
}

func (x *sqlUserStoreDB) getRecentPasswordsForUser(userId UserId) ([]string, error) {
	passwords := make([]string, 0)

	var currentPassword string
	if errCurPasswordScan := x.db.QueryRow("SELECT password FROM authuserpwd WHERE userid = $1", userId).Scan(&currentPassword); errCurPasswordScan != nil {
		return passwords, errCurPasswordScan
	}
	passwords = append(passwords, currentPassword)

	rows, err := x.db.Query("SELECT password FROM authpwdarchive WHERE userid = $1 ORDER BY created DESC LIMIT 15", userId)
	if err != nil {
		return passwords, err
	}
	defer rows.Close()

	for rows.Next() {
		var passwordDbHash string
		errScan := rows.Scan(&passwordDbHash)
		if errScan != nil {
			return passwords, errScan
		}
		passwords = append(passwords, passwordDbHash)
	}
	return passwords, nil
}

func (x *sqlUserStoreDB) identityExists(tx *sql.Tx, identity string) (bool, error) {
	id, err := x.findUser(tx, identity, identity, []UserId{})
	return id != 0, err
}

func createSQLSet(userIDs []UserId) string {
	if len(userIDs) == 0 {
		// Postgres doesn't like an empty set "()", so we disallow it
		panic("createSQLSet needs a non-empty list")
	}
	b := strings.Builder{}
	b.WriteRune('(')
	for i, id := range userIDs {
		b.WriteString(strconv.FormatInt(int64(id), 10))
		if i != len(userIDs)-1 {
			b.WriteRune(',')
		}
	}
	b.WriteRune(')')
	return b.String()
}

// findUser searches for given email address or username, but ignores any users specified in excludeUsers
// tx is optional. If nil, then we query against the DB.
// If email AND username are provided, then we find the first record that matches EITHER of them (we don't specify which!)
// If the user does not exist, returns (0, nil)
// If the user exists, returns (UserID, nil)
// Anything else returns (0, Error)
func (x *sqlUserStoreDB) findUser(tx *sql.Tx, email string, username string, excludeUsers []UserId) (UserId, error) {
	s := ""
	params := []interface{}{}
	if email != "" && username != "" {
		s = "SELECT userid FROM authuserstore WHERE (LOWER(email) = $1 OR LOWER(username) = $2)"
		params = append(params, CanonicalizeIdentity(email))
		params = append(params, CanonicalizeIdentity(username))
	} else if email != "" {
		s = "SELECT userid FROM authuserstore WHERE (LOWER(email) = $1)"
		params = append(params, CanonicalizeIdentity(email))
	} else if username != "" {
		s = "SELECT userid FROM authuserstore WHERE (LOWER(username) = $1)"
		params = append(params, CanonicalizeIdentity(username))
	} else {
		return 0, errors.New("Neither email nor username provided to findUser")
	}
	s += " AND (archived = false OR archived IS NULL)"
	if len(excludeUsers) != 0 {
		s += " AND userid NOT IN " + createSQLSet(excludeUsers)
	}

	userID := int64(0)
	var err error
	if tx != nil {
		err = tx.QueryRow(s, params...).Scan(&userID)
	} else {
		err = x.db.QueryRow(s, params...).Scan(&userID)
	}
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return UserId(userID), err
}

func (x *sqlUserStoreDB) LockAccount(userId UserId) error {
	if _, err := x.db.Exec(`UPDATE authuserpwd SET accountlocked = true WHERE userId = $1;`, userId); err != nil {
		return err
	}
	return nil
}

func (x *sqlUserStoreDB) UnlockAccount(userId UserId) error {
	if _, err := x.db.Exec(`UPDATE authuserpwd SET accountlocked = false WHERE userId = $1;`, userId); err != nil {
		return err
	}
	return nil
}

func (x *sqlUserStoreDB) CreateIdentity(user *AuthUser, password string) (UserId, error) {
	hash, ehash := computeAuthausHash(password)
	if ehash != nil {
		return NullUserId, ehash
	}

	existingUserID, err := x.findUser(nil, user.Email, user.Username, []UserId{})
	if existingUserID != 0 {
		return existingUserID, ErrIdentityExists
	} else if err != nil {
		return NullUserId, err
	}

	// Insert into user store
	if tx, etx := x.db.Begin(); etx == nil {
		if _, eCreateUserStore := tx.Exec(`INSERT INTO authuserstore " +
		" (email, username, firstname, lastname, mobile, phone, remarks, created, createdby, modified, modifiedby, archived, authusertype, externalUUID) " +
		" VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, user.Telephonenumber, user.Remarks,
			user.Created, user.CreatedBy, user.Modified, user.ModifiedBy, false, user.Type, user.ExternalUUID); eCreateUserStore != nil {
			tx.Rollback()
			return NullUserId, eCreateUserStore
		}

		// Get user id
		var userId int64
		if len(user.Username) > 0 {
			row := tx.QueryRow(`SELECT userid FROM authuserstore WHERE LOWER(username) = $1 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(user.Username))
			if scanErr := row.Scan(&userId); scanErr != nil {
				tx.Rollback()
				return NullUserId, scanErr

			}
		} else {
			row := tx.QueryRow(`SELECT userid FROM authuserstore WHERE LOWER(email) = $1 AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(user.Email))
			if scanErr := row.Scan(&userId); scanErr != nil {
				tx.Rollback()
				return NullUserId, scanErr
			}
		}

		if user.Type == UserTypeDefault {
			if _, eCreateAuthUser := tx.Exec(`INSERT INTO authuserpwd (userid, password) VALUES ($1, $2)`, userId, hash); eCreateAuthUser != nil {
				//fmt.Printf("Insert into authuserpwd failed because: %v\n", eCreateAuthUser)
				if strings.Index(eCreateAuthUser.Error(), "duplicate key") != -1 {
					eCreateAuthUser = ErrIdentityExists
				}
				tx.Rollback()
				return NullUserId, eCreateAuthUser
			}
		}

		if eCommit := tx.Commit(); eCommit != nil {
			return NullUserId, eCommit
		}
		return UserId(userId), nil
	} else {
		return NullUserId, etx
	}
}

func (x *sqlUserStoreDB) UpdateIdentity(user *AuthUser) error {
	existingUserID, err := x.findUser(nil, user.Email, user.Username, []UserId{user.UserId})
	if existingUserID != 0 {
		return ErrIdentityExists
	} else if err != nil {
		return err
	}

	if tx, etx := x.db.Begin(); etx == nil {
		if update, eupdate := tx.Exec(`UPDATE authuserstore SET email = $1, username = $2, firstname = $3, lastname = $4, mobile = $5, phone = $6, remarks = $7, modified= $8, modifiedby = $9, authusertype = $10 WHERE userid = $11 AND (archived = false OR archived IS NULL)`, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, user.Telephonenumber, user.Remarks, user.Modified, user.ModifiedBy, user.Type, user.UserId); eupdate == nil {
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
		// Check if the new name exists (and is not archived)
		if exists, err := x.identityExists(tx, newIdent); err != nil {
			return err
		} else if exists {
			return ErrIdentityExists
		}

		if update, eupdate := tx.Exec(`UPDATE authuserstore SET email = $1 WHERE LOWER(email) = $2 AND (archived = false OR archived IS NULL)`, newIdent, CanonicalizeIdentity(oldIdent)); eupdate == nil {
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

func (x *sqlUserStoreDB) GetIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) {
	sqlStatement := "SELECT aus.userid, aus.email, aus.username, aus.firstname, aus.lastname, aus.mobile, aus.phone, " +
		" aus.remarks, aus.created, aus.createdby, aus.modified, aus.modifiedby, aus.authusertype, " +
		" aus.archived, aus.externaluuid, pwd.updated, pwd.accountlocked" +
		" FROM authuserstore aus LEFT JOIN authuserpwd pwd ON aus.userid = pwd.userid"
	if getIdentitiesFlag&GetIdentitiesFlagDeleted == 0 {
		sqlStatement += " WHERE aus.archived = false OR aus.archived IS NULL"
	}
	rows, err := x.db.Query(sqlStatement)
	if err != nil {
		return []AuthUser{}, err
	}
	defer rows.Close()
	result := make([]AuthUser, 0)
	type sqlUser struct {
		userId               sql.NullInt64
		email                sql.NullString
		username             sql.NullString
		firstName            sql.NullString
		lastName             sql.NullString
		mobileNumber         sql.NullString
		telephoneNumber      sql.NullString
		remarks              sql.NullString
		created              pq.NullTime
		createdBy            sql.NullInt64
		modified             pq.NullTime
		modifiedBy           sql.NullInt64
		authUserType         sql.NullInt64
		archived             sql.NullBool
		externalUUID         sql.NullString
		passwordModifiedDate pq.NullTime
		accountLocked        sql.NullBool
	}
	for rows.Next() {
		user := sqlUser{}
		if err := rows.Scan(&user.userId, &user.email, &user.username, &user.firstName, &user.lastName, &user.mobileNumber,
			&user.telephoneNumber, &user.remarks, &user.created, &user.createdBy, &user.modified, &user.modifiedBy,
			&user.authUserType, &user.archived, &user.externalUUID, &user.passwordModifiedDate, &user.accountLocked); err != nil {
			return []AuthUser{}, err
		}
		au := AuthUser{
			UserId:               UserId(user.userId.Int64),
			Email:                user.email.String,
			Username:             user.username.String,
			Firstname:            user.firstName.String,
			Lastname:             user.lastName.String,
			Mobilenumber:         user.mobileNumber.String,
			Telephonenumber:      user.telephoneNumber.String,
			Remarks:              user.remarks.String,
			Created:              user.created.Time,
			CreatedBy:            UserId(user.createdBy.Int64),
			Modified:             user.modified.Time,
			ModifiedBy:           UserId(user.modifiedBy.Int64),
			Type:                 AuthUserType(user.authUserType.Int64),
			Archived:             user.archived.Bool,
			ExternalUUID:         user.externalUUID.String,
			PasswordModifiedDate: user.passwordModifiedDate.Time,
			AccountLocked:        user.accountLocked.Bool,
		}
		result = append(result, au)
	}
	if rows.Err() != nil {
		return []AuthUser{}, rows.Err()
	}
	return result, nil
}

func (x *sqlUserStoreDB) GetUserFromIdentity(identity string) (AuthUser, error) {
	return getUserFromIdentity(x.db, identity)
}

func (x *sqlUserStoreDB) GetUserFromUserId(userId UserId) (AuthUser, error) {
	return getUserFromUserId(x.db, userId)
}

func getUserFromIdentity(db *sql.DB, identity string) (AuthUser, error) {
	return getUser(db.QueryRow("SELECT aus.userid, aus.email, aus.username, aus.firstname, aus.lastname, aus.mobile, aus.phone, aus.remarks, aus.created, aus.createdby, aus.modified, aus.modifiedby, aus.authusertype, aus.archived, aus.externaluuid, pwd.updated, pwd.accountlocked FROM authuserstore aus LEFT JOIN authuserpwd pwd ON aus.userid = pwd.userid WHERE (LOWER(aus.email) = $1 OR LOWER(aus.username) = $1) AND (aus.archived = false OR aus.archived IS NULL)", CanonicalizeIdentity(identity)))
}

func getUserFromUserId(db *sql.DB, userId UserId) (AuthUser, error) {
	return getUser(db.QueryRow("SELECT aus.userid, aus.email, aus.username, aus.firstname, aus.lastname, aus.mobile, aus.phone, aus.remarks, aus.created, aus.createdby, aus.modified, aus.modifiedby, aus.authusertype, aus.archived, aus.externaluuid, pwd.updated, pwd.accountlocked FROM authuserstore aus LEFT JOIN authuserpwd pwd ON aus.userid = pwd.userid WHERE aus.userid = $1 AND (aus.archived = false OR aus.archived IS NULL)", userId))
}

func getUser(row *sql.Row) (AuthUser, error) {
	type sqlUser struct {
		userId               sql.NullInt64
		email                sql.NullString
		username             sql.NullString
		firstName            sql.NullString
		lastName             sql.NullString
		mobileNumber         sql.NullString
		telephoneNumber      sql.NullString
		remarks              sql.NullString
		created              pq.NullTime
		createdBy            sql.NullInt64
		modified             pq.NullTime
		modifiedBy           sql.NullInt64
		authUserType         sql.NullInt64
		archived             sql.NullBool
		externalUUID         sql.NullString
		passwordModifiedDate pq.NullTime
		accountLocked        sql.NullBool
	}
	user := sqlUser{}
	if err := row.Scan(&user.userId, &user.email, &user.username, &user.firstName, &user.lastName, &user.mobileNumber, &user.telephoneNumber,
		&user.remarks, &user.created, &user.createdBy, &user.modified, &user.modifiedBy, &user.authUserType, &user.archived, &user.externalUUID,
		&user.passwordModifiedDate, &user.accountLocked); err != nil {
		if strings.Index(err.Error(), "no rows in result set") == -1 {
			return AuthUser{}, err
		}
		return AuthUser{}, ErrIdentityAuthNotFound
	}

	au := AuthUser{
		UserId:               UserId(user.userId.Int64),
		Email:                user.email.String,
		Username:             user.username.String,
		Firstname:            user.firstName.String,
		Lastname:             user.lastName.String,
		Mobilenumber:         user.mobileNumber.String,
		Telephonenumber:      user.telephoneNumber.String,
		Remarks:              user.remarks.String,
		Created:              user.created.Time,
		CreatedBy:            UserId(user.createdBy.Int64),
		Modified:             user.modified.Time,
		ModifiedBy:           UserId(user.modifiedBy.Int64),
		Type:                 AuthUserType(user.authUserType.Int64),
		Archived:             user.archived.Bool,
		ExternalUUID:         user.externalUUID.String,
		PasswordModifiedDate: user.passwordModifiedDate.Time,
		AccountLocked:        user.accountLocked.Bool,
	}

	return au, nil
}

func (x *sqlUserStoreDB) Close() {
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlSessionDB struct {
	db *sql.DB
}

func (x *sqlSessionDB) Write(sessionkey string, token *Token) error {
	// We convert 'token.expires' to UTC before putting it in the DB, as the column, Expires, is TIMESTAMP without timezone, and it returns a time equivalent to UTC.
	_, err := x.db.Exec(`INSERT INTO authsession (sessionkey, userid, permit, expires) VALUES($1, $2, $3, $4)`, sessionkey, token.UserId, token.Permit.Serialize(), token.Expires.UTC())

	return err
}

func (x *sqlSessionDB) Read(sessionkey string) (*Token, error) {
	x.purgeExpiredSessions()
	row := x.db.QueryRow(`SELECT userid, permit, expires FROM authsession WHERE sessionkey = $1`, sessionkey)
	token := &Token{}
	epermit := ""
	var userId int64
	if err := row.Scan(&userId, &epermit, &token.Expires); err != nil {
		return nil, ErrInvalidSessionToken
	} else {
		if err := token.Permit.Deserialize(epermit); err != nil {
			return nil, ErrInvalidSessionToken
		} else {
			token.UserId = UserId(userId)
			user, err := getUserFromUserId(x.db, token.UserId)
			if err != nil {
				return nil, ErrInvalidSessionToken
			}
			token.Username = user.Username
			token.Email = user.Email
			if user.Type == UserTypeLDAP {
				token.Identity = user.Username
			} else {
				token.Identity = user.Email
			}

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
}

func (x *sqlSessionDB) purgeExpiredSessions() {
	x.db.Exec(`DELETE FROM authsession WHERE expires < $1`, time.Now().UTC())
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
	defer rows.Close()
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

func NewUserStoreDB_SQL(db *sql.DB) (UserStore, error) {
	userStore := new(sqlUserStoreDB)
	userStore.db = db
	return userStore, nil
}

func NewSessionDB_SQL(db *sql.DB) (SessionDB, error) {
	sessions := new(sqlSessionDB)
	sessions.db = db
	return sessions, nil
}

func NewPermitDB_SQL(db *sql.DB) (PermitDB, error) {
	permits := new(sqlPermitDB)
	permits.db = db
	return permits, nil
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
