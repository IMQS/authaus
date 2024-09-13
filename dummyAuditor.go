package authaus

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

type dummyAuditor struct {
	testing  *testing.T
	messages []string
}

func (d *dummyAuditor) AuditUserAction(identity, item, context string, auditActionType AuditActionType) {
	if identity == "" {
		assert.Fail(d.testing, "Identity should not be empty")
	} else {
		s := fmt.Sprintf("Identity: %v, Item: %v, Context: %v, Action: %v", identity, item, context, auditActionType)
		d.messages = append(d.messages, s)
	}
}
