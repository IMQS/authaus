// ldapfetch is a utility to fetch and display users from an LDAP server
// based on a given LDAP json configuration file matching ConfigLDAP structure
//
// Usage: ldapfetch <path to config>
package main

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"github.com/IMQS/log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ldapfetch <path to config>")
		os.Exit(1)
	}
	s, e := os.ReadFile(os.Args[1])
	if e != nil {
		fmt.Println("Error reading config file:", e)
		os.Exit(1)
	}
	var ldapConf *authaus.ConfigLDAP
	e = json.Unmarshal(s, &ldapConf)

	if e != nil {
		fmt.Println("Error parsing config file:", e)
		os.Exit(1)
	}
	if !ldapConf.DebugUserPull {
		fmt.Println("Warning: DebugUserPull is not enabled in the config - " +
			"you may not get extra user info from LDAP")
	}

	ldapImpl := authaus.LdapImpl{
		Config: ldapConf,
	}
	logger := log.New(log.Stdout, true)
	users, e := ldapImpl.GetLdapUsers(logger)
	if e != nil {
		fmt.Println("Error getting ldap users:", e)
		os.Exit(1)
	}
	fmt.Printf("%d Auth users mapped\n", len(users))
	fmt.Printf("%25v | %25v | %40v\n",
		"Username", "Firstname", "Lastname")
	fmt.Printf("%s\n", "------------------------------------------------------------------------------------------"+
		"------")
	for _, user := range users {
		fmt.Printf("%25v | %25v | %40v\n",
			user.Username, user.Firstname, user.Lastname)
	}
}
