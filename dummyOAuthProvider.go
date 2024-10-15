package authaus

import "github.com/IMQS/log"

type dummyOAuthProvider struct {
	Log *log.Logger
}

func (d dummyOAuthProvider) setLogger(logger *log.Logger) {
	d.Log = logger
}

func (d dummyOAuthProvider) entraRefreshHTTP(id string, provider *ConfigOAuthProvider, token oauthToken) (oauthToken, error) {
	//TODO implement me
	panic("implement me")
}
