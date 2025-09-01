package authaus

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Authenticator/Userstore that simply stores identity/passwords in memory
type dummyUserStore struct {
	users           map[UserId]*dummyUser
	usersLock       sync.RWMutex
	passswordExpiry time.Duration
}

type dummyUser struct {
	userId               UserId
	email                string
	username             string
	firstname            string
	lastname             string
	mobilenumber         string
	telephonenumber      string
	remarks              string
	created              time.Time
	createdby            UserId
	modified             time.Time
	modifiedby           UserId
	password             string
	passwordResetToken   string
	archived             bool
	authUserType         AuthUserType
	passwordModifiedDate time.Time
	accountLocked        bool
	internalUUID         string
	externalUUID         string
}

func newDummyLdap() *dummyLdap {
	d := &dummyLdap{}
	d.ldapUsers = make([]*dummyLdapUser, 0)
	return d
}

func newDummyUserStore() *dummyUserStore {
	d := &dummyUserStore{}
	d.users = make(map[UserId]*dummyUser)
	return d
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (x *dummyUserStore) Authenticate(identity, password string, authTypeCheck AuthCheck) error {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	user := x.getDummyUser(identity)
	if user == nil {
		return ErrIdentityAuthNotFound
	}
	if user.accountLocked {
		return ErrAccountLocked
	}
	if user.password != password {
		return ErrInvalidPassword
	}
	return nil
}

func (x *dummyUserStore) Close() {
	//Set incrementing user id to 0, for unit test prediction
	nextUserId = 0
}

func (x *dummyUserStore) SetConfig(passwordExpiry time.Duration, oldPasswordHistorySize int, usersExemptFromExpiring []string) error {
	x.passswordExpiry = passwordExpiry
	return nil
}

func (x *dummyUserStore) SetPassword(userId UserId, password string, enforceTypeCheck PasswordEnforcement) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && user.authUserType.CanSetPassword() {
		if enforceTypeCheck&PasswordEnforcementReuse != 0 && user.password == password {
			return ErrInvalidPastPassword
		}
		user.password = password
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) ResetPasswordStart(userId UserId, expires time.Time) (string, error) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived && user.authUserType.CanSetPassword() {
		user.passwordResetToken = generatePasswordResetToken(expires)
		return user.passwordResetToken, nil
	} else {
		return "", ErrIdentityAuthNotFound
	}
}

func (x *dummyUserStore) ResetPasswordFinish(userId UserId, token string, password string, enforceTypeCheck PasswordEnforcement) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived && user.authUserType.CanSetPassword() {
		if err := verifyPasswordResetToken(token, user.passwordResetToken); err != nil {
			return err
		}
		if enforceTypeCheck&PasswordEnforcementReuse != 0 && user.password == password {
			return ErrInvalidPastPassword
		}
		user.password = password
		user.passwordResetToken = ""
		return nil
	}
	return ErrIdentityAuthNotFound
}

func (x *dummyUserStore) CreateIdentity(user *AuthUser, password string) (UserId, error) {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	var userD *dummyUser
	userD = x.getDummyUser(user.Email)
	if userD == nil {
		if user.InternalUUID == "" {
			uuid, _ := uuid.NewRandom()
			user.InternalUUID = uuid.String()
		}
		userId := x.generateUserId()
		x.users[userId] = &dummyUser{userId, user.Email, user.Username, user.Firstname, user.Lastname, user.Mobilenumber, user.Telephonenumber, user.Remarks, user.Created, user.CreatedBy,
			user.Modified, user.ModifiedBy, password, "", user.Archived, user.Type, user.PasswordModifiedDate, user.AccountLocked, user.InternalUUID, user.ExternalUUID}
		return userId, nil
	} else {
		return NullUserId, ErrIdentityExists
	}
}

func (x *dummyUserStore) UpdateIdentity(user *AuthUser) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if userD, exists := x.users[user.UserId]; exists && !userD.archived {
		userD.email = user.Email
		userD.username = user.Username
		userD.firstname = user.Firstname
		userD.lastname = user.Lastname
		userD.mobilenumber = user.Mobilenumber
		userD.telephonenumber = user.Telephonenumber
		userD.remarks = user.Remarks
		userD.modified = user.Modified
		userD.modifiedby = user.ModifiedBy
		userD.authUserType = user.Type
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) ArchiveIdentity(userId UserId) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists {
		user.archived = true
	} else {
		return ErrIdentityAuthNotFound
	}
	return nil
}

func (x *dummyUserStore) MatchArchivedUserExtUUID(externalUUID string) (bool, UserId, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()
	for _, v := range x.users {
		if v.archived && v.externalUUID == externalUUID {
			return true, v.userId, nil
		}
	}
	return false, NullUserId, nil
}

func (x *dummyUserStore) UnarchiveIdentity(userId UserId) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists {
		user.archived = false
		return nil
	} else {
		return ErrIdentityAuthNotFound
	}
}

func (x *dummyUserStore) SetUserStats(userId UserId, action string) error {
	return errors.New("not implemented")
}

func (x *dummyUserStore) GetUserStats(userId UserId) (UserStats, error) {
	return UserStats{}, errors.New("not implemented")
}

func (x *dummyUserStore) GetUserStatsAll() (map[UserId]UserStats, error) {
	return nil, errors.New("not implemented")
}

func (x *dummyUserStore) RenameIdentity(oldEmail, newEmail string) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()

	newKey := CanonicalizeIdentity(newEmail)
	oldEmail = CanonicalizeIdentity(oldEmail)
	newUser := x.getDummyUser(newKey)
	if newUser == nil {
		oldUser := x.getDummyUser(oldEmail)

		if oldUser != nil && !oldUser.archived && oldUser.authUserType == UserTypeDefault {
			x.users[oldUser.userId].email = newEmail
			return nil
		} else {
			return ErrIdentityAuthNotFound
		}
	} else {
		return ErrIdentityExists
	}
}

func (x *dummyUserStore) GetIdentities(getIdentitiesFlag GetIdentitiesFlag) ([]AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	list := []AuthUser{}
	for _, v := range x.users {
		if (getIdentitiesFlag&GetIdentitiesFlagDeleted == 0) && v.archived {
			continue
		}
		list = append(list, AuthUser{v.userId, v.email, v.username, v.firstname, v.lastname, v.mobilenumber, v.telephonenumber, v.remarks, v.created, v.createdby, v.modified, v.modifiedby, v.authUserType, v.archived, v.internalUUID, v.externalUUID, v.passwordModifiedDate, v.accountLocked})
	}
	return list, nil
}

func (x *dummyUserStore) LockAccount(userId UserId) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived {
		user.accountLocked = true
	}
	return nil
}

func (x *dummyUserStore) UnlockAccount(userId UserId) error {
	x.usersLock.Lock()
	defer x.usersLock.Unlock()
	if user, exists := x.users[userId]; exists && !user.archived {
		user.accountLocked = false
	}
	return nil
}

func (x *dummyUserStore) GetUserFromIdentity(identity string) (*AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	for _, v := range x.users {
		if CanonicalizeIdentity(v.email) == CanonicalizeIdentity(identity) && v.archived == false {
			return &AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType, PasswordModifiedDate: v.passwordModifiedDate, AccountLocked: v.accountLocked, InternalUUID: v.internalUUID}, nil
		} else if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) && v.archived == false {
			return &AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType, PasswordModifiedDate: v.passwordModifiedDate, AccountLocked: v.accountLocked, InternalUUID: v.internalUUID}, nil
		}
	}

	return nil, ErrIdentityAuthNotFound
}

func (x *dummyUserStore) GetUserFromUserId(userId UserId) (*AuthUser, error) {
	x.usersLock.RLock()
	defer x.usersLock.RUnlock()

	for _, v := range x.users {
		if v.userId == userId && v.archived == false {
			return &AuthUser{UserId: v.userId, Email: v.email, Username: v.username, Firstname: v.firstname, Lastname: v.lastname, Mobilenumber: v.mobilenumber, Type: v.authUserType, PasswordModifiedDate: v.passwordModifiedDate, InternalUUID: v.internalUUID}, nil
		}
	}

	return nil, ErrIdentityAuthNotFound
}

func (x *dummyUserStore) getDummyUser(identity string) *dummyUser {
	for _, v := range x.users {
		if CanonicalizeIdentity(v.email) == CanonicalizeIdentity(identity) && v.archived == false {
			return v
		} else if CanonicalizeIdentity(v.username) == CanonicalizeIdentity(identity) && v.archived == false {
			return v
		}
	}
	return nil
}

func (x *dummyUserStore) generateUserId() UserId {
	nextUserId = nextUserId + 1
	return nextUserId
}
