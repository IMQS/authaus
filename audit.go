package authaus

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/IMQS/serviceauth"
)

type Auditor interface {
	AuditUserAction(identity, password, actionDescription string)
}

type Action struct {
	Who     string         `json:"who"`
	DidWhat string         `json:"did_what"`
	ToWhat  string         `json:"to_what"`
	AtTime  int64          `json:"at_time"`
	Context *ActionContext `json:"context"`
}

type ActionContext struct {
	Location string `json:"location"`
}

func (x *Central) AuditUserAction(identity, password, actionDescription string) {
	action := &Action{}
	action.Who = identity
	action.DidWhat = actionDescription
	action.ToWhat = "IMQS Web V8"
	action.AtTime = time.Now().Unix()

	actionContext := &ActionContext{}
	actionContext.Location = time.Now().Location().String()
	action.Context = actionContext

	client := &http.Client{}
	actionStr, _ := json.Marshal(action)

	req, err := http.NewRequest("POST", x.AuditServiceUrl, bytes.NewBuffer(actionStr))
	if err != nil {
		x.Log.Infof("Error creating audit request: (%v)", err)
	}

	req.Header.Add("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	req.Header.Set("Content-Type", "application/json")

	err = serviceauth.CreateInterServiceRequest(req, actionStr)
	if err != nil {
		x.Log.Infof("Error creating audit interservice request: (%v)", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		x.Log.Infof("Error calling audit service: (%v)", err)
	}
	resp.Body.Close()
}
