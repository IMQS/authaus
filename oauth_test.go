package authaus

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

//func getCentralOAuth(t *testing.T) *Central {
//	var userStore UserStore
//	var sessionDB SessionDB
//	var permitDB PermitDB
//	var roleDB RoleGroupDB
//	var msaad MSAAD
//	var oauth OAuth
//}

func TestOAuth_Initialize(t *testing.T) {
	c := getCentralMSAAD(t)
	assert.NotNil(t, c)

	req, err := http.NewRequest(http.MethodGet, "/path", nil)
	if err != nil {
		// Handle error
	}
	req.Form = make(map[string][]string)
	req.Form.Add("provider", "test")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(c.OAuth.HttpHandlerOAuthStart)
	handler.ServeHTTP(rr, req)

	// Check the status code and other assertions
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Response body: %v", rr.Body.String())
	} else {
		t.Logf("Response body: %v", rr.Body.String())
	}
}
