// ldapfetch is a utility to fetch and display users from an LDAP server
// based on a given LDAP json configuration file matching ConfigLDAP structure
//
// Usage: ldapfetch <path to config>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"strings"

	"github.com/IMQS/authaus"
	"github.com/IMQS/log"
)

type cliOptions struct {
	verbose bool
	showExp bool
}

type expiryEntry struct {
	username string
	expires  time.Time
}

func usage() {
	fmt.Println("Usage: ldapfetch <path to config> [v] [e]")
	fmt.Println("  v: full output (all println/debug output)")
	fmt.Println("  e: print expired and imminent expiry users (next 5 days)")
}

func parseOptions(args []string) (cliOptions, error) {
	opts := cliOptions{}
	for _, arg := range args {
		letters := strings.TrimPrefix(arg, "-")
		if letters == "" {
			return opts, fmt.Errorf("empty option: %q", arg)
		}
		for _, ch := range letters {
			switch ch {
			case 'v':
				opts.verbose = true
			case 'e':
				opts.showExp = true
			default:
				return opts, fmt.Errorf("unknown option: %q", string(ch))
			}
		}
	}
	return opts, nil
}

func buildExpiryEntries(users []authaus.AuthUser, byUser map[string]time.Time) []expiryEntry {
	out := make([]expiryEntry, 0, len(users))
	for _, user := range users {
		expiry, ok := byUser[user.Username]
		if !ok {
			continue
		}
		out = append(out, expiryEntry{username: user.Username, expires: expiry})
	}
	return out
}

func printExpirySection(entries []expiryEntry) {
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, 5)

	expired := make([]expiryEntry, 0)
	imminent := make([]expiryEntry, 0)
	for _, entry := range entries {
		if !entry.expires.After(now) {
			expired = append(expired, entry)
		} else if !entry.expires.After(cutoff) {
			imminent = append(imminent, entry)
		}
	}

	sort.Slice(expired, func(i, j int) bool { return expired[i].expires.Before(expired[j].expires) })
	sort.Slice(imminent, func(i, j int) bool { return imminent[i].expires.Before(imminent[j].expires) })

	fmt.Println()
	fmt.Println("=== Expiry Report (next 5 days) ===")
	fmt.Println("Expired users:")
	if len(expired) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, user := range expired {
			fmt.Printf("  %s | %s\n", user.username, user.expires.Format(time.RFC3339))
		}
	}

	fmt.Println("Imminent expiry users:")
	if len(imminent) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, user := range imminent {
			fmt.Printf("  %s | %s\n", user.username, user.expires.Format(time.RFC3339))
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	opts, err := parseOptions(os.Args[2:])
	if err != nil {
		fmt.Println("Error parsing options:", err)
		usage()
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
	if opts.verbose && !ldapConf.DebugUserPull {
		fmt.Println("Warning: DebugUserPull is not enabled in the config - " +
			"you may not get extra user info from LDAP")
	}

	ldapConfForFetch := ldapConf
	if !opts.verbose {
		cloned := *ldapConf
		cloned.DebugUserPull = false
		ldapConfForFetch = &cloned
	}

	ldapImpl := authaus.NewAuthenticator_LDAP(ldapConfForFetch)
	logger := log.New(log.Stdout, true)
	users, expiryByUser, e := ldapImpl.GetLdapUsersWithExpiry(logger)
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

	if opts.showExp || opts.verbose {
		expiryEntries := buildExpiryEntries(users, expiryByUser)
		printExpirySection(expiryEntries)
	}
}
