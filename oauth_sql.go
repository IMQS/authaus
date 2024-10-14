package authaus

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IMQS/log"
	"time"
)

type OAuthDB struct {
	db     *sql.DB
	log    *log.Logger
	Config ConfigOAuth
}

func (x *OAuthDB) getToken(id string) (string, time.Time, *oauthToken, error) {
	var token oauthToken
	var tokenStr string
	var providerStr string
	var timeVal time.Time

	err := x.db.QueryRow("SELECT provider, updated, token FROM oauthsession WHERE id = $1", id).Scan(&providerStr, &timeVal, &tokenStr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil, err
	}
	if err := json.Unmarshal([]byte(tokenStr), &token); err != nil {
		return "", time.Time{}, nil, fmt.Errorf("Error unmarshalling token %v from database: %w", id[:6], err)
	}
	return providerStr, timeVal, &token, err
}

func (x *OAuthDB) getOrphanAuthSessions() (sessions []string, err error) {
	rows, err := x.db.Query(`SELECT sessionkey FROM authsession WHERE oauthid IS NOT NULL AND oauthid NOT IN (SELECT id FROM oauthsession)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		key := ""
		if err := rows.Scan(&key); err != nil {
			x.log.Warnf("Error scanning invalid oauth sessions: %v", err)
			return
		}
		sessions = append(sessions, key)
	}
	return sessions, nil
}

// Delete OAuth sessions from our database, which have no link to an Authaus session.
func (x *OAuthDB) purgeUnusedOAuthSessions() {
	// Add some grace period, because the DB inserts/updates between OAuth and other Authaus
	// tables are not done in the same DB commit.
	grace := time.Minute
	olderThan := time.Now().Add(-grace).UTC()
	_, err := x.db.Exec(`DELETE FROM oauthsession WHERE id NOT IN (SELECT oauthid FROM authsession WHERE oauthid IS NOT NULL) AND created < $1`, olderThan)
	if err != nil {
		x.log.Warnf("Failed to purge unused oauth sessions from DB: %v", err)
	}
}

func (x *OAuthDB) deleteSession(id string) error {
	//TODO implement me
	//panic("implement me")
	if _, err := x.db.Exec("DELETE FROM oauthsession WHERE id = $1", id); err != nil {
		return err
		//x.parent.Log.Warnf("Error deleting from oauthsession table for unconfigured provider '%v'", session.provider)
	}
	//}
	//	x.parent.Log.Infof("Deleted oauthsession session %v... for unconfigured provider '%v'", session.id[:4], session.provider)
	//else {
	return nil
}

func (x *OAuthDB) getSessions() ([]oauthSession, error) {
	//TODO implement me
	//panic("implement me")
	var sessions []oauthSession
	if rows, err := x.db.Query("SELECT id, provider FROM oauthsession"); err != nil {
		x.log.Warnf("OAuth validateTokens failed to read oauthsession from DB: %v", err)
		return nil, err
	} else {
		defer rows.Close()
		for rows.Next() {
			id := ""
			provider := ""
			if err := rows.Scan(&id, &provider); err != nil {
				x.log.Warnf("OAuth validateTokens failed to scan oauthsession from DB: %v", err)
				return nil, err
			}
			sessions = append(sessions, oauthSession{
				id:       id,
				provider: provider,
			})
		}
	}
	return sessions, nil
}

func (x *OAuthDB) updateToken(utc time.Time, newToken *oauthToken, id string) error {
	//TODO implement me
	//panic("implement me")
	_, err := x.db.Exec("UPDATE oauthsession SET updated = $1, token = $2 WHERE id = $3", utc, newToken.toJSON(), id)
	if err != nil {
		return fmt.Errorf("Error updating token %v in database: %w", id[:6], err)
	}
	return nil
}
