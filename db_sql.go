package authaus

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
	hashLengthV1                  = 65
	scryptN_V1                    = 256
	defaultOldPasswordHistorySize = 15
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type scannable interface {
	Scan(dest ...interface{}) error
}

type sqlUserStoreDB struct {
	db                      *sql.DB
	passwordExpiry          time.Duration
	oldPasswordHistorySize  int      // When enforcing "may not re-use old password" policy, look back this many entries to find old (and therefore invalid) passwords
	usersExemptFromExpiring []string // List of users that are not subject to password expiry. Username will be used for comparison.
}

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
	internalUUID         sql.NullString
	externalUUID         sql.NullString
	passwordModifiedDate pq.NullTime
	accountLocked        sql.NullBool
}

func (user *sqlUser) toAuthUser() *AuthUser {
	return &AuthUser{
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
		InternalUUID:         user.internalUUID.String,
		ExternalUUID:         user.externalUUID.String,
		PasswordModifiedDate: user.passwordModifiedDate.Time,
		AccountLocked:        user.accountLocked.Bool,
	}
}

func (x *sqlUserStoreDB) SetConfig(passwordExpiry time.Duration, oldPasswordHistorySize int, usersExemptFromExpiring []string) error {
	if passwordExpiry != 0 {
		x.passwordExpiry = passwordExpiry
	}
	if oldPasswordHistorySize != 0 {
		x.oldPasswordHistorySize = oldPasswordHistorySize
	}
	if len(usersExemptFromExpiring) > 0 {
		x.usersExemptFromExpiring = usersExemptFromExpiring
	}

	return nil
}

func (x *sqlUserStoreDB) ExemptFromExpiryCheck(username string) bool {
	for _, user := range x.usersExemptFromExpiring {
		if user == username {
			return true
		}
	}
	return false
}

func (x *sqlUserStoreDB) Authenticate(identity, password string, authTypeCheck AuthCheck) error {
	row := x.db.QueryRow(`SELECT userid, username FROM authuserstore WHERE (LOWER(email) = $1 OR LOWER(username) = $1) AND (archived = false OR archived IS NULL)`, CanonicalizeIdentity(identity))
	var userId int64
	var username string
	if err := row.Scan(&userId, &username); err != nil {
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

	if x.passwordExpiry != 0 && authTypeCheck&AuthCheckPasswordExpired != 0 && !x.ExemptFromExpiryCheck(username) {
		if lastUpdated.Add(x.passwordExpiry).Before(time.Now()) {
			return ErrPasswordExpired
		}
	}
	return nil
}

func (x *sqlUserStoreDB) SetPassword(userId UserId, password string, enforceTypeCheck PasswordEnforcement) error {
	var tx *sql.Tx
	var err error
	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()
	if enforceTypeCheck&PasswordEnforcementReuse != 0 && x.hasPasswordBeenUsedBefore(userId, password) {
		return ErrInvalidPastPassword
	}
	if err = x.archivePassword(tx, userId); err != nil {
		return fmt.Errorf("Could not archive password: %v", err)
	}
	if err = x.setPasswordInternal(tx, userId, password); err != nil {
		return fmt.Errorf("Could not update password: %v", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %v", err)
	}

	return nil
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
	var tx *sql.Tx
	var err error
	if tx, err = x.db.Begin(); err != nil {
		return "", fmt.Errorf("Could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	token := generatePasswordResetToken(expires)
	update, err := tx.Exec(`UPDATE authuserpwd AS aup SET pwdtoken = $1
	FROM authuserstore AS aus
	WHERE
		aus.userid = aup.userid AND aup.userid = $2
		AND (aus.archived = false OR aus.archived IS NULL)
		AND aus.authusertype = $3`,
		token, userId, UserTypeDefault,
	)
	if err != nil {
		return "", fmt.Errorf("Could not execute update statement (ResetPasswordStart): %w", err)
	}
	if affected, err := update.RowsAffected(); err != nil {
		return "", fmt.Errorf("Could not execute find UserID record (ResetPasswordStart): %w", err)
	} else if affected != 1 {
		return "", fmt.Errorf("Could not find UserID record (ResetPasswordStart): %w", ErrIdentityAuthNotFound)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("Could not commit transaction: %w", err)
	}
	return token, nil
}

func (x *sqlUserStoreDB) ResetPasswordFinish(userId UserId, token string, password string, enforceTypeCheck PasswordEnforcement) error {
	var (
		truthToken sql.NullString
		tx         *sql.Tx
		err        error
	)

	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()

	if err = tx.QueryRow("SELECT pwdtoken FROM authuserpwd WHERE userid = $1", userId).Scan(&truthToken); err != nil {
		if err == sql.ErrNoRows {
			return ErrIdentityAuthNotFound
		}
		return fmt.Errorf("Could not read pwdtoken: %w", err)
	}
	if err = verifyPasswordResetToken(token, truthToken.String); err != nil {
		return fmt.Errorf("Could not verify password reset token: %w", err)
	}
	if enforceTypeCheck&PasswordEnforcementReuse != 0 && x.hasPasswordBeenUsedBefore(userId, password) {
		return ErrInvalidPastPassword
	}
	if err = x.archivePassword(tx, userId); err != nil {
		return fmt.Errorf("Could not archive password: %w", err)
	}
	if err = x.setPasswordInternal(tx, userId, password); err != nil {
		return fmt.Errorf("Could not reset password: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %w", err)
	}
	return nil

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

	rows, err := x.db.Query("SELECT password FROM authpwdarchive WHERE userid = $1 ORDER BY created DESC LIMIT $2", userId, x.oldPasswordHistorySize)
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

	if user.InternalUUID == "" {
		if uuid, err := uuid.NewRandom(); err != nil {
			return NullUserId, err
		} else {
			user.InternalUUID = uuid.String()
		}
	}

	// Insert into user store
	if tx, etx := x.db.Begin(); etx == nil {
		externalUUID := &user.ExternalUUID
		if user.ExternalUUID == "" {
			externalUUID = nil
		}
		if _, eCreateUserStore := tx.Exec(`INSERT INTO authuserstore `+
			` (email, username, firstname, lastname, mobile, phone, remarks, created, createdby, modified, modifiedby, archived, authusertype, internalUUID, externalUUID) `+
			` VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, user.Telephonenumber, user.Remarks,
			user.Created, user.CreatedBy, user.Modified, user.ModifiedBy, false, user.Type, user.InternalUUID, externalUUID); eCreateUserStore != nil {
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

	var (
		externalUUID *string
		tx           *sql.Tx
	)
	if user.ExternalUUID != "" {
		externalUUID = &user.ExternalUUID
	}
	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()

	update, err := tx.Exec(`UPDATE authuserstore SET email = $1, username = $2, firstname = $3, lastname = $4, mobile = $5, phone = $6, `+
		`remarks = $7, modified = $8, modifiedby = $9, authusertype = $10, externaluuid = $11`+
		` WHERE userid = $12 AND (archived = false OR archived IS NULL)`,
		user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, user.Telephonenumber,
		user.Remarks, user.Modified, user.ModifiedBy, user.Type, externalUUID, user.UserId)
	if err != nil {
		return fmt.Errorf("Could not update identity: %v", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return fmt.Errorf("User could not be updated: %w", ErrIdentityAuthNotFound)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %v", err)
	}
	return nil
}

func (x *sqlUserStoreDB) ArchiveIdentity(userId UserId) error {
	var tx *sql.Tx
	var err error
	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()
	update, err := tx.Exec(`UPDATE authuserstore SET archived = $1, archive_date = NOW() WHERE userid = $2`, true, userId)
	if err != nil {
		return fmt.Errorf("Could not update auth user: %w", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return fmt.Errorf("User could not be updated: %w", ErrIdentityAuthNotFound)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %w", err)
	}
	return nil
}

// UnarchiveIdentity
func (x *sqlUserStoreDB) UnarchiveIdentity(userId UserId) error {
	var tx *sql.Tx
	var err error
	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()
	update, err := tx.Exec(`UPDATE authuserstore SET archived = $1, archive_date = NULL WHERE userid = $2`, false, userId)
	if err != nil {
		return fmt.Errorf("Could not update auth user: %w", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return fmt.Errorf("User could not be updated: %w", ErrIdentityAuthNotFound)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %w", err)
	}

	return nil
}

func (x *sqlUserStoreDB) SetUserStats(userId UserId, action string) error {
	var tx *sql.Tx
	var err error
	var update sql.Result

	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("could not begin transaction: %v", err)
	}
	defer tx.Rollback()

	switch action {
	case UserStatActionLogin:
		update, err = tx.Exec(`INSERT INTO authuserstats (user_id, last_login_date)
							   VALUES ($1, NOW())
							   ON CONFLICT (user_id) 
							   DO UPDATE SET last_login_date = NOW()`, userId)
	case UserStatActionEnable:
		update, err = tx.Exec(`INSERT INTO authuserstats (user_id, enabled_date, disabled_date)
							   VALUES ($1, NOW(), NULL)
							   ON CONFLICT (user_id) 
							   DO UPDATE SET enabled_date = NOW(), disabled_date = NULL`, userId)

	case UserStatActionDisable:
		update, err = tx.Exec(`INSERT INTO authuserstats (user_id, enabled_date, disabled_date)
							   VALUES ($1, NULL, NOW())
							   ON CONFLICT (user_id)
							   DO UPDATE SET enabled_date = NULL, disabled_date = NOW()`, userId)
	default:
		return fmt.Errorf("invalid UserStatAction: %v", action)
	}
	if err != nil {
		return fmt.Errorf("could not update auth user stats: %v", err)
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return fmt.Errorf("user stats could not be updated, affected rows: %d", affected)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %v", err)
	}
	return nil
}

func (x *sqlUserStoreDB) GetUserStats(userId UserId) (userStats, error) {
	var stats userStats

	// enabled_date disabled_date ast_login_date

	row := x.db.QueryRow(`SELECT user_id, enabled_date, disabled_date, last_login_date FROM authuserstats WHERE user_id = $1`, userId)
	err := row.Scan(&stats.UserId, &stats.EnabledDate, &stats.DisabledDate, &stats.LastLoginDate)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No record found, return empty stats without error
			return stats, nil
		}
		return stats, fmt.Errorf("could not scan user stats: %v", err)
	}

	return stats, nil
}

// MatchArchivedUserExtUUID MatchArchiveUser
//
// Best effort to identify a previously archived user from external sources.
// In the simple approach we need to match on externaluuid,
// taking the assumption that, at least in principle, the user must still
// be the same user if the externaluuid has not changed.
// For historic reasons, there may be multiple exact matches of archived
// users, so we will just return the newest id.

func (x *sqlUserStoreDB) MatchArchivedUserExtUUID(externalUUID string) (bool, UserId, error) {
	if externalUUID == "" {
		return false, NullUserId, fmt.Errorf("ExternalUUID is empty")
	}
	var userId sql.NullInt64
	sqlStr := "SELECT " +
		"aus.userid" + " FROM authuserstore aus  WHERE aus.externaluuid = $1 AND (aus.archived = true) order by modified desc limit 1"
	row := x.db.QueryRow(sqlStr, externalUUID)
	if err := row.Scan(&userId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, NullUserId, nil
		} else {
			return false, NullUserId, err
		}
	}
	if userId.Valid {
		return true, UserId(userId.Int64), nil
	} else {
		return false, NullUserId, fmt.Errorf("Found user, but userId is null")
	}
}

func (x *sqlUserStoreDB) RenameIdentity(oldIdent, newIdent string) error {
	var (
		tx     *sql.Tx
		err    error
		update sql.Result
	)

	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()
	// Check if the new name exists (and is not archived)
	if exists, err := x.identityExists(tx, newIdent); err != nil {
		return fmt.Errorf("Could not determine if identity exists: %v", err)
	} else if exists {
		return ErrIdentityExists
	}
	if update, err = tx.Exec(`UPDATE authuserstore SET email = $1 WHERE LOWER(email) = $2 AND (archived = false OR archived IS NULL)`, newIdent, CanonicalizeIdentity(oldIdent)); err != nil {
		return fmt.Errorf("Could not update record: %v", err)
	}
	if affected, _ := update.RowsAffected(); err != nil {
		return fmt.Errorf("")
	} else if affected != 1 {
		return fmt.Errorf("No rows were affected during update: %v", ErrIdentityAuthNotFound)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %v", err)
	}
	return nil
}

func selectUsersSQL() string {
	return "SELECT " +
		"aus.userid, " +
		"aus.email, " +
		"aus.username, " +
		"aus.firstname, " +
		"aus.lastname, " +
		"aus.mobile, " +
		"aus.phone, " +
		"aus.remarks, " +
		"aus.created, " +
		"aus.createdby, " +
		"aus.modified, " +
		"aus.modifiedby, " +
		"aus.authusertype, " +
		"aus.archived, " +
		"aus.internaluuid, " +
		"aus.externaluuid, " +
		"pwd.updated, " +
		"pwd.accountlocked " +
		" FROM authuserstore aus LEFT JOIN authuserpwd pwd ON aus.userid = pwd.userid"
}

func selectUsersScan(rows scannable) (*AuthUser, error) {
	user := sqlUser{}
	if err := rows.Scan(&user.userId, &user.email, &user.username, &user.firstName, &user.lastName, &user.mobileNumber,
		&user.telephoneNumber, &user.remarks, &user.created, &user.createdBy, &user.modified, &user.modifiedBy,
		&user.authUserType, &user.archived, &user.internalUUID, &user.externalUUID,
		&user.passwordModifiedDate, &user.accountLocked); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("While scanning user, no rows were found: %v", err)
		}
		return nil, fmt.Errorf("Could not scan user: %v", err)
	}
	return user.toAuthUser(), nil
}

func (x *sqlUserStoreDB) GetIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) {
	sqlStatement := selectUsersSQL()
	if getIdentitiesFlag&GetIdentitiesFlagDeleted == 0 {
		sqlStatement += " WHERE aus.archived = false OR aus.archived IS NULL"
	}
	rows, err := x.db.Query(sqlStatement)
	if err != nil {
		return []AuthUser{}, err
	}
	defer rows.Close()
	result := make([]AuthUser, 0)
	for rows.Next() {
		au, err := selectUsersScan(rows)
		if err != nil {
			return []AuthUser{}, err
		}
		result = append(result, *au)
	}
	if rows.Err() != nil {
		return []AuthUser{}, rows.Err()
	}
	return result, nil
}

func (x *sqlUserStoreDB) GetUserFromIdentity(identity string) (*AuthUser, error) {
	return getUserFromIdentity(x.db, identity)
}

func (x *sqlUserStoreDB) GetUserFromUserId(userId UserId) (*AuthUser, error) {
	return getUserFromUserId(x.db, userId)
}

func getUserFromIdentity(db *sql.DB, identity string) (*AuthUser, error) {
	sqlStr := selectUsersSQL() + " WHERE (LOWER(aus.email) = $1 OR LOWER(aus.username) = $1) AND (aus.archived = false OR aus.archived IS NULL)"
	return selectUsersScan(db.QueryRow(sqlStr, CanonicalizeIdentity(identity)))
}

func getUserFromUserId(db *sql.DB, userId UserId) (*AuthUser, error) {
	sqlStr := selectUsersSQL() + " WHERE aus.userid = $1 AND (aus.archived = false OR aus.archived IS NULL)"
	return selectUsersScan(db.QueryRow(sqlStr, userId))
}

func (x *sqlUserStoreDB) Close() {
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlSessionDB struct {
	db *sql.DB
}

func (x *sqlSessionDB) Write(sessionkey string, token *Token) error {
	var oauthID *string
	if token.OAuthSessionID != "" {
		oauthID = &token.OAuthSessionID
	}
	_, err := x.db.Exec(`INSERT INTO authsession (sessionkey, userid, permit, expires, internaluuid, oauthid) VALUES($1, $2, $3, $4, $5, $6)`,
		sessionkey, token.UserId, token.Permit.Serialize(), token.Expires.UTC(), token.InternalUUID, oauthID)

	return err
}

func (x *sqlSessionDB) Read(sessionkey string) (*Token, error) {
	x.purgeExpiredSessions()
	row := x.db.QueryRow(`SELECT userid, permit, expires, internaluuid, oauthid FROM authsession WHERE sessionkey = $1`, sessionkey)
	token := &Token{}
	epermit := ""
	var userId int64
	oauthID := sql.NullString{}
	if err := row.Scan(&userId, &epermit, &token.Expires, &token.InternalUUID, &oauthID); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidSessionToken
		} else {
			return nil, err
		}
	} else {
		return x.populateToken(token, epermit, userId, oauthID)
	}
}

func (x *sqlSessionDB) populateToken(token *Token, epermit string, userId int64, oauthID sql.NullString) (*Token, error) {
	if err := token.Permit.Deserialize(epermit); err != nil {
		return nil, err
	}
	token.UserId = UserId(userId)
	user, err := getUserFromUserId(x.db, token.UserId)
	if err != nil {
		return nil, err
	}
	token.Username = user.Username
	token.Email = user.Email
	if user.Type == UserTypeLDAP {
		token.Identity = user.Username
	} else {
		token.Identity = user.Email
	}
	if oauthID.Valid {
		token.OAuthSessionID = oauthID.String
	}

	return token, nil
}

func (x *sqlSessionDB) GetAllTokens(includeExpired bool) ([]*Token, error) {
	type scanResult struct {
		userId  int64
		permit  string
		oAuthID sql.NullString
		token   *Token
	}

	var r *sql.Rows
	var e error
	query := `SELECT userid, permit, expires, internaluuid, oauthid FROM authsession`
	if includeExpired {
		r, e = x.db.Query(query)
	} else {
		query += ` WHERE expires > $1`
		r, e = x.db.Query(query, time.Now())
	}

	if e != nil {
		return nil, e
	}

	defer r.Close()
	var scanResults []*scanResult
	var tokens []*Token
	for r.Next() {
		s := scanResult{
			userId:  0,
			permit:  "",
			oAuthID: sql.NullString{},
			token:   &Token{},
		}

		if err := r.Scan(&s.userId, &s.permit, &s.token.Expires, &s.token.InternalUUID, &s.oAuthID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrInvalidSessionToken
			} else {
				return nil, err
			}
		} else {
			scanResults = append(scanResults, &s)
		}
	}
	for _, s := range scanResults {
		if t, err := x.populateToken(s.token, s.permit, s.userId, s.oAuthID); err != nil {
			continue
		} else {
			tokens = append(tokens, t)
		}
	}
	return tokens, nil
}

func (x *sqlSessionDB) GetAllOAuthTokenIDs() ([]string, error) {
	db := x.db
	ids := make([]string, 0)
	r, err := db.Query("SELECT id, token FROM oauthsession")
	if err != nil {
		return nil, sql.ErrNoRows
	}
	for r.Next() {
		var id string
		var tokenStr string
		var token Token
		r.Scan(&id, &tokenStr)
		if err := json.Unmarshal([]byte(tokenStr), &token); err != nil {
			return nil, fmt.Errorf("error unmarshalling token %v from database: %w", id[:6], err)
		}
		ids = append(ids, id)
	}
	return ids, nil
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
	var tx *sql.Tx
	var err error
	encodedPermit := permit.Serialize()
	if tx, err = x.db.Begin(); err != nil {
		return fmt.Errorf("Could not begin transaction: %v", err)
	}
	defer tx.Rollback()
	update, err := tx.Exec(`UPDATE authuserpwd SET permit = $1, updated = $2 WHERE userid = $3`, encodedPermit, time.Now().UTC(), userId)
	if affected, _ := update.RowsAffected(); affected != 1 {
		if _, err = tx.Exec(`INSERT INTO authuserpwd (userid, permit) VALUES ($1, $2)`, userId, encodedPermit); err != nil {
			return fmt.Errorf("Could neither update nor insert permit: %v", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("Could not commit transaction: %v", err)
	}
	return nil
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
		if !strUserId.Valid {
			return nil, fmt.Errorf("Could not parse ID into number: %v", err)
		}
		if userID, err := strconv.ParseInt(strUserId.String, 10, 64); err == nil {
			permits[UserId(userID)] = p
		}
	}
	return permits, err
}

func verifyAuthausHash(password, hash string) bool {
	block, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	if len(block) != hashLengthV1 {
		return false
	}
	if block[0] != 1 {
		return false
	}
	scrypted, err := scrypt.Key([]byte(password), block[1:33], scryptN_V1, 8, 1, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(block[33:], scrypted) == 1
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
	userStore.oldPasswordHistorySize = defaultOldPasswordHistorySize
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
