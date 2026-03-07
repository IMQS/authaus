package authaus

import (
	"github.com/IMQS/log"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestLDAPUserDiffSame(t *testing.T) {
	// Test the user diff function with two identical users
	userBefore := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              time.Now(),
		CreatedBy:            UserIdLDAPMerge,
		Modified:             time.Now(),
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: time.Now(),
		AccountLocked:        false,
	}
	now := time.Now()
	userAfter := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              now,
		CreatedBy:            UserIdLDAPMerge,
		Modified:             now,
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: now,
		AccountLocked:        false,
	}
	diff, e := UserInfoDiff(userBefore, userAfter)
	assert.Nil(t, e, "Error should be nil")
	assert.Empty(t, diff, "Diff should be empty")
}

func TestLDAPUserDiffDiff(t *testing.T) {
	// Test all diff on all fields and exclusion of ignored fields
	userBefore := AuthUser{
		Email:                "john@doe.com",
		Username:             "JohnDoe",
		Firstname:            "John",
		Lastname:             "Doe",
		Mobilenumber:         "080 555 5555",
		Telephonenumber:      "021 888 5555",
		Remarks:              "Before comment",
		Created:              time.Now(),
		CreatedBy:            UserIdLDAPMerge,
		Modified:             time.Now(),
		ModifiedBy:           UserIdMSAADMerge,
		Type:                 UserTypeLDAP,
		Archived:             false,
		InternalUUID:         "3342-3342-3342-3342",
		ExternalUUID:         "4438-4438-4438-4438",
		PasswordModifiedDate: time.Now(),
		AccountLocked:        false,
	}
	userAfter := AuthUser{
		Email:                "john@doe.com1",
		Username:             "JohnDoe1",
		Firstname:            "John1",
		Lastname:             "Doe1",
		Mobilenumber:         "080 555 55551",
		Telephonenumber:      "021 888 55515",
		Remarks:              "Before comment1",
		Created:              time.Now().Add(time.Minute),
		CreatedBy:            UserIdAdministrator,
		Modified:             time.Now().Add(time.Minute),
		ModifiedBy:           UserIdAdministrator,
		Type:                 UserTypeLDAP,
		Archived:             true,
		InternalUUID:         "3342-3342-3342-33421",
		ExternalUUID:         "4438-4438-4438-44381",
		PasswordModifiedDate: time.Now().Add(time.Minute),
		AccountLocked:        true,
	}
	excludeFields := []string{"created", "createdBy", "modified", "modifiedBy", "passwordModifiedDate"}
	diff, e := UserInfoDiff(userBefore, userAfter)
	assert.Nil(t, e, "Error should be nil")
	assert.NotEmpty(t, diff)
	for _, field := range excludeFields {
		assert.NotContains(t, diff, field, "Field %v should not be in the diff", field)
	}
	t.Logf("User diff: \n%v", diff)
}

func Test_printTrunc(t *testing.T) {
	type args struct {
		name         string
		maxLength    int
		abbrevString string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Short string no trunc",
			args: args{"This is a test string", 25, "..."},
			want: "This is a test string",
		},
		{
			name: "Short string limit",
			args: args{"This is a test string xxx", 25, "..."},
			want: "This is a test string xxx",
		},
		{
			name: "Over by 1",
			args: args{"This is a test string x y z", 25, "..."},
			want: "This is a test string ...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, printTrunc(tt.args.name, tt.args.maxLength, tt.args.abbrevString), "printTrunc(%v, %v, %v)", tt.args.name, tt.args.maxLength, tt.args.abbrevString)
		})
	}
}

func Test_extractPath(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want []pathElement
	}{
		{
			name: "empty DN",
			dn:   "",
			want: []pathElement{},
		},
		{
			name: "single DC component",
			dn:   "DC=com",
			want: []pathElement{{name: "com", nodeType: "DC"}},
		},
		{
			name: "normal DN",
			dn:   "CN=John Doe,OU=Users,DC=example,DC=com",
			want: []pathElement{
				{name: "com", nodeType: "DC"},
				{name: "example", nodeType: "DC"},
				{name: "Users", nodeType: "OU"},
				{name: "John Doe", nodeType: "CN"},
			},
		},
		{
			name: "DN with spaces around separators",
			dn:   "CN=Jane , OU=Staff , DC=corp , DC=org",
			want: []pathElement{
				{name: "org", nodeType: "DC"},
				{name: "corp", nodeType: "DC"},
				{name: "Staff", nodeType: "OU"},
				{name: "Jane", nodeType: "CN"},
			},
		},
		{
			name: "malformed element with no equals sign",
			dn:   "nodns",
			want: []pathElement{},
		},
		{
			name: "element with equals at end (empty value) is filtered out",
			dn:   "DC=com,OU=",
			want: []pathElement{{name: "com", nodeType: "DC"}},
		},
		{
			name: "value containing an equals sign",
			dn:   "CN=John=Doe,DC=com",
			want: []pathElement{
				{name: "com", nodeType: "DC"},
				{name: "John=Doe", nodeType: "CN"},
			},
		},
		{
			name: "mixed valid and malformed elements",
			dn:   "CN=Alice,badpart,DC=example",
			want: []pathElement{
				{name: "example", nodeType: "DC"},
				{name: "Alice", nodeType: "CN"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPath(tt.dn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_extractHierarchy(t *testing.T) {
	t.Run("empty search result", func(t *testing.T) {
		sr := &ldap.SearchResult{}
		root := extractHierarchy(sr)
		assert.NotNil(t, root)
		assert.Equal(t, "ROOT", root.name)
		assert.Equal(t, "ROOT", root.nodeType)
		assert.Empty(t, root.children)
	})

	t.Run("single entry builds correct tree", func(t *testing.T) {
		sr := &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{DN: "CN=John Doe,OU=Users,DC=example,DC=com"},
			},
		}
		root := extractHierarchy(sr)
		assert.NotNil(t, root)

		// Expect: ROOT → com → example → Users → John Doe
		comNode, ok := root.children["com"]
		assert.True(t, ok, "expected 'com' child under ROOT")
		assert.Equal(t, "DC", comNode.nodeType)

		exampleNode, ok := comNode.children["example"]
		assert.True(t, ok, "expected 'example' child under 'com'")
		assert.Equal(t, "DC", exampleNode.nodeType)

		usersNode, ok := exampleNode.children["Users"]
		assert.True(t, ok, "expected 'Users' child under 'example'")
		assert.Equal(t, "OU", usersNode.nodeType)

		johnNode, ok := usersNode.children["John Doe"]
		assert.True(t, ok, "expected 'John Doe' child under 'Users'")
		assert.Equal(t, "CN", johnNode.nodeType)
		assert.Empty(t, johnNode.children)
	})

	t.Run("multiple entries share common path components", func(t *testing.T) {
		sr := &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{DN: "CN=Alice,OU=Users,DC=example,DC=com"},
				{DN: "CN=Bob,OU=Users,DC=example,DC=com"},
				{DN: "CN=Carol,OU=Admins,DC=example,DC=com"},
			},
		}
		root := extractHierarchy(sr)

		comNode := root.children["com"]
		assert.NotNil(t, comNode)
		exampleNode := comNode.children["example"]
		assert.NotNil(t, exampleNode)

		// Both OUs should be present
		assert.Len(t, exampleNode.children, 2)

		usersNode := exampleNode.children["Users"]
		assert.NotNil(t, usersNode)
		assert.Contains(t, usersNode.children, "Alice")
		assert.Contains(t, usersNode.children, "Bob")

		adminsNode := exampleNode.children["Admins"]
		assert.NotNil(t, adminsNode)
		assert.Contains(t, adminsNode.children, "Carol")
	})

	t.Run("entry with malformed DN produces no children", func(t *testing.T) {
		sr := &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{DN: "nodns"},
			},
		}
		root := extractHierarchy(sr)
		assert.NotNil(t, root)
		assert.Empty(t, root.children)
	})
}

func Test_printHierarchy(t *testing.T) {
	logger := log.NewTesting(t)

	t.Run("nil node does not panic", func(t *testing.T) {
		// This test checks that calling printHierarchy with a nil node does not panic.
		assert.NotPanics(t, func() {
			printHierarchy(nil, "", false, logger)
		})
		// No output is asserted, as formatHierarchyPath is not called for nil.
	})

	t.Run("single node with OU type formats slash-separated path", func(t *testing.T) {
		logger := log.NewTesting(t)
		node := &hierarchyNode{
			name:     "Users",
			nodeType: "OU",
			children: make(map[string]*hierarchyNode),
		}
		assert.NotPanics(t, func() {
			printHierarchy(node, "ROOT", false, logger)
		})
		path := formatHierarchyPath("ROOT", node.name, node.nodeType, false)
		assert.Equal(t, "ROOT/Users", path)
	})

	t.Run("CN node with printNodesIfCN=true formats colon-separated path", func(t *testing.T) {
		node := &hierarchyNode{
			name:     "John Doe",
			nodeType: "CN",
			children: make(map[string]*hierarchyNode),
		}
		assert.NotPanics(t, func() {
			printHierarchy(node, "ROOT/example/Users", true, logger)
		})
		path := formatHierarchyPath("ROOT/example/Users", node.name, node.nodeType, true)
		assert.Equal(t, "ROOT/example/Users : John Doe", path)
	})

	t.Run("tree with children recurses without panic", func(t *testing.T) {
		child := &hierarchyNode{
			name:     "John Doe",
			nodeType: "CN",
			children: make(map[string]*hierarchyNode),
		}
		parent := &hierarchyNode{
			name:     "Users",
			nodeType: "OU",
			children: map[string]*hierarchyNode{"John Doe": child},
		}
		assert.NotPanics(t, func() {
			printHierarchy(parent, "ROOT", false, logger)
		})
	})
}

func Test_formatHierarchyPath(t *testing.T) {
	t.Run("OU node returns slash-separated path", func(t *testing.T) {
		got := formatHierarchyPath("ROOT", "Users", "OU", false)
		assert.Contains(t, got, "ROOT/Users")
	})

	t.Run("CN node with printNodesIfCN=false returns slash-separated path", func(t *testing.T) {
		got := formatHierarchyPath("ROOT/Users", "John Doe", "CN", false)
		assert.Contains(t, got, "ROOT/Users/John Doe")
	})

	t.Run("CN node with printNodesIfCN=true returns colon-separated path", func(t *testing.T) {
		got := formatHierarchyPath("ROOT/Users", "John Doe", "CN", true)
		assert.Contains(t, got, "ROOT/Users : John Doe")
	})

	// Ensure the generated path exceeds 120 characters for truncation
	t.Run("truncation works for long paths", func(t *testing.T) {
		prefix := strings.Repeat("a", 130)
		longNode := strings.Repeat("b", 20)
		got := formatHierarchyPath(prefix, longNode, "OU", false)
		assert.True(t, len(got) <= 120, "Output should be truncated to 120 characters or less")
		assert.True(t, strings.HasSuffix(got, "..."), "Output should end with '...'")
	})
}
