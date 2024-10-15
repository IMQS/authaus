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

func (x *OAuthDB) Initialize(logger *log.Logger) {
	x.purgeUnusedOAuthSessions()
	x.purgeExpiredChallenges()
	x.setLogger(logger)
}

func (x *OAuthDB) setLogger(logger *log.Logger) {
	x.log = logger
}

func (x *OAuthDB) insertChallenge(id string, providerName string, created time.Time, nonce string, pkceVerifier string) error {
	if _, err := x.db.Exec("INSERT INTO oauthchallenge (id, provider, created, nonce, pkce_verifier) VALUES ($1, $2, $3, $4, $5)",
		id, providerName, time.Now().UTC(), nonce, pkceVerifier); err != nil {
		x.log.Errorf("Failed to insert OAuth challenge %v: %v", id[:6], err)
		return err
	}
	return nil
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
		if err = rows.Scan(&key); err != nil {
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

func (x *OAuthDB) purgeExpiredChallenges() {
	expired := time.Now().Add(-x.Config.LoginExpiry())
	if x.Config.Verbose {
		// This is racy, because another thread could do the DELETE while we're reading,
		// but for debugging with a small number of initial users, should be sufficient for our needs.
		rows, err := x.db.Query("SELECT id FROM oauthchallenge WHERE created < $1", expired)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				id := ""
				if err = rows.Scan(&id); err != nil {
					x.log.Errorf("Error reading id from oauthchallenge during verbose readout")
				} else {
					x.log.Infof("Purging expired oauth challenge '%v'", id[:6])
				}
			}
		}
	}
	x.db.Exec("DELETE FROM oauthchallenge WHERE created < $1", expired)
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
func (x *OAuthDB) getChallenge(id string) (provider, codeVerifier string, err error) {
	// Is this a timing attack vector (ie the DB query on the secret 'id')?
	// Even if we are vulnerable here, we can get around this by verifying the nonce without a timing weakness
	err = x.db.QueryRow("SELECT provider, pkce_verifier FROM oauthchallenge WHERE id = $1", id).Scan(&provider, &codeVerifier)
	return
}

// Delete an oauthchallenge record, and insert a new record into oauthsession, with the new token details
func (x *OAuthDB) upgradeChallengeToSession(id string, token *oauthToken) error {
	db := x.db
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if x.Config.Verbose {
		x.log.Infof("Upgrading oauth challenge '%v'", id[:6])
	}

	if x.Config.ForceFastTokenRefresh {
		x.log.Infof("During challenge upgrade, decreasing expiry time from %v to %v, for testing", token.ExpiresIn, 120)
		token.ExpiresIn = 120
	}

	_, err = tx.Exec("INSERT INTO oauthsession SELECT id,provider,created,$1 FROM oauthchallenge WHERE id = $2", time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("Error inserting into oauthsession: %w", err)
	}
	_, err = tx.Exec("DELETE FROM oauthchallenge WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("Error deleting from oauthchallenge: %w", err)
	}
	_, err = tx.Exec("UPDATE oauthsession SET token = $1 WHERE id = $2", token.toJSON(), id)
	if err != nil {
		return fmt.Errorf("Error updating oauthsession with initial token: %w", err)
	}
	return tx.Commit()
}

func (x *OAuthDB) getLastSession() (id string, err error) {
	err = x.db.QueryRow("SELECT id FROM oauthsession ORDER BY updated DESC LIMIT 1").Scan(&id)
	return
}
