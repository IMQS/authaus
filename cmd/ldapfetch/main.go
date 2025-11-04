package main

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ldapfetch <path to ldapauth.json>")
		return
	}
	s, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var ldapConf *authaus.ConfigLDAP
	e = json.Unmarshal(s, &ldapConf)

	if e != nil {
		panic(fmt.Errorf("error unmarshalling config: %w", e))
	}
	if !ldapConf.DebugUserPull {
		fmt.Println("Warning: DebugUserPull is not enabled in the config - you may not get any users returned")
	}

	ldapImpl := authaus.LdapImpl{
		Config: ldapConf,
	}
	users, e := ldapImpl.GetLdapUsers()
	if e != nil {
		panic(fmt.Errorf("error: %v", e))
	}
	for _, user := range users {
		fmt.Printf("User: %v\n", user.Firstname)
	}
}
