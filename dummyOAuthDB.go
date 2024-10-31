package authaus

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/log"
	"sync"
	"time"
)

type dummyOAuthDB struct {
	Log           *log.Logger
	challengeLock sync.Mutex // Protects the following fields
	challenges    map[string]*challenge
	sessionLock   sync.Mutex // Protects the following fields
	sessions      map[string]*oauthSessionRecord
	SessionDB     SessionDB
}

func (d *dummyOAuthDB) Initialize(logger *log.Logger) {
	d.challenges = make(map[string]*challenge)
	d.sessions = make(map[string]*oauthSessionRecord)
	d.setLogger(logger)
}

type challenge struct {
	id           string
	providerName string
	created      time.Time
	nonce        string
	pckeVerifier string
}

type oauthSessionRecord struct {
	id       string
	provider string
	created  time.Time
	updated  time.Time
	token    string
}

func (d *dummyOAuthDB) setLogger(logger *log.Logger) {
	d.Log = logger
}

func (d *dummyOAuthDB) getToken(id string) (string, time.Time, *oauthToken, error) {
	//x.db.QueryRow("SELECT provider, updated, token FROM oauthsession WHERE id = $1", id).Scan(&providerStr, &timeVal, &tokenStr)
	fmt.Println("getToken")
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	session := d.sessions[id]
	if session == nil {
		return "", time.Time{}, nil, fmt.Errorf("Session not found")
	} else {
		//providerStr, timeVal, &token, err
		var token *oauthToken
		if err := json.Unmarshal([]byte(session.token), &token); err != nil {
			return "", time.Time{}, nil, fmt.Errorf("Error unmarshalling token %v from database: %w", id[:6], err)
		}
		return session.provider, session.updated, token, nil
	}
}

func (d *dummyOAuthDB) updateToken(utc time.Time, newToken *oauthToken, id string) error {
	//x.db.Exec("UPDATE oauthsession SET updated = $1, token = $2 WHERE id = $3", utc, newToken.toJSON(), id)
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	session := d.sessions[id]
	session.updated = utc
	session.token = newToken.toJSON()
	return nil
}

func (d *dummyOAuthDB) getSessions() ([]oauthSession, error) {
	sessions := make([]oauthSession, 0)
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	for _, s := range d.sessions {
		sessions = append(sessions, oauthSession{
			id:       s.id,
			provider: s.provider,
		})
	}
	return sessions, nil
}

func (d *dummyOAuthDB) deleteSession(id string) error {
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	delete(d.sessions, id)
	return nil
}

func (d *dummyOAuthDB) getOrphanAuthSessions() (sessions []string, err error) {
	// SELECT sessionkey FROM authsession WHERE oauthid IS NOT NULL AND oauthid NOT IN (SELECT id FROM oauthsession)
	// Return Auth sessions which have an OAuth ID, but the OAuth ID does not exist in the OAuth session table
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	tokens, err := d.SessionDB.GetAllOAuthTokenIDs()
	if err != nil {
		d.Log.Errorf("Failed to get all tokens: %v", err)
		return nil, err
	}
	for _, t := range tokens {
		if _, ok := d.sessions[t]; !ok {
			sessions = append(sessions, t)
		}
	}
	return sessions, nil
}

func (d *dummyOAuthDB) purgeUnusedOAuthSessions() {
	//DELETE FROM oauthsession WHERE id NOT IN (SELECT oauthid FROM authsession WHERE oauthid IS NOT NULL) AND created < $1
	//Delete OAuth sessions which has no link to an Authaus session, after some grace period (grace period is 1 minute)
	tokens, err := d.SessionDB.GetAllTokens(true)
	if err != nil {
		d.Log.Errorf("Failed to get all tokens: %v", err)
		return
	}
	var toDelete []string
	// TODO : This is obviously super inefficient. We should replace with a map.
	// But then again it is test code...
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	for id, s := range d.sessions {
		found := false
		for _, t := range tokens {
			if id == t.OAuthSessionID {
				found = true
			}
		}
		if !found && time.Since(s.created) > time.Minute {
			toDelete = append(toDelete, id)
		}
	}
	for _, id := range toDelete {
		delete(d.sessions, id)
	}
}

func (d *dummyOAuthDB) purgeExpiredChallenges() {
	d.challengeLock.Lock()
	defer d.challengeLock.Unlock()
	for id, c := range d.challenges {
		// TODO - make configurable
		if time.Since(c.created) > 5*time.Second {
			delete(d.challenges, id)
		}
	}
}

func (d *dummyOAuthDB) insertChallenge(id string, providerName string, created time.Time, nonce string, pckeVerifier string) error {
	d.challengeLock.Lock()
	defer d.challengeLock.Unlock()
	d.challenges[id] = &challenge{
		id:           id,
		providerName: providerName,
		created:      created,
		nonce:        nonce,
		pckeVerifier: pckeVerifier,
	}

	return nil
}

func (d *dummyOAuthDB) getChallenge(id string) (provider, codeVerifier string, err error) {
	d.challengeLock.Lock()
	defer d.challengeLock.Unlock()
	if c, ok := d.challenges[id]; ok {
		return c.providerName, c.pckeVerifier, nil
	} else {
		return "", "", fmt.Errorf("Challenge %v not found", id)
	}
}

func (d *dummyOAuthDB) upgradeChallengeToSession(id string, token *oauthToken) error {
	fmt.Println("upgradeChallengeToSession")
	fmt.Printf("id: %s\n", id)
	fmt.Printf("upgradeChallenge...token: %s\n", token.AccessToken)
	d.challengeLock.Lock()
	defer d.challengeLock.Unlock()
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	if c, ok := d.challenges[id]; ok {
		//d.SessionDB.Read(c.id)
		d.sessions[id] = &oauthSessionRecord{
			id:       c.id,
			provider: c.providerName,
			created:  c.created,
			updated:  time.Now().UTC(),
			token:    token.toJSON(),
		}
		delete(d.challenges, id)
		return nil
	} else {
		return fmt.Errorf("Challenge %v not found", id)
	}
}

func (d *dummyOAuthDB) getLastSession() (string, error) {
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()
	lastDate := time.Time{}
	for _, s := range d.sessions {
		if lastDate.Before(s.created) {
			lastDate = s.created
		}
		return s.id, nil
	}
	return "", fmt.Errorf("No sessions found")
}
