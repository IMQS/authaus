# Changelog

## Current

## v1.3.9

* feat : Add provider function to retrieve visible Entra groups (ASG-4959)

## v1.3.8

* fix : Add fetch-all for UserStats to combat performance issues 

## v1.3.7

* feat : Add the Termination date, Last Login date, Disabled date and Enabled date to the "User List" export (NEXUS-4245)

## v1.3.6

* feat : Make UserInfoDiff public (NEXUS-4317)
* feat : New function UserDiffLogMessage
* feat : Make UserInfoToJSON public

## v1.3.5

* feat : Add LDAP user change diff to audit trail (NEXUS-4248)
* fix : Incorrect username recorded for LDAP sync changes
* fix : Incorrect username recorded for MSAAD sync changes
* fix : Bumped vulnerable version of crypto

## v1.3.4

* feat : Add MSAAD audit log for user details/group update (ASG-3268)

## v1.3.3

* feat : Add enabled and disabled audit user types (NEXUS-4244)

## v1.1.2

* fix : Fix oauth initialization bug

## v1.1.1

* fix : Auth dies when MSAAD config or ClientID in MSAAD config is missing.

## v1.1.0 (retracted)

* ASG-3355 : MSAAD Unarchive feature
* feat : Implement unarchive method (checks "allowarchive")
* fix : Username not set on msaad user create
* fix : Fix audit log double entry
* fix : bug in dummyUserStore.go (ignored fields)
* fix : db tests (waitgroups)
* fix : unit tests
* fix : Refactor Graph calls
* fix : Remove unused / temp functionality
* fix : Remove 'Domain' MSAAD config field

## v1.0.37 

* fix: Remove exposed client secret from redirect 

## v1.0.36

* fix: Harden MSAAD sync (ASG-3350)

## v1.0.35

* feat: New methods on db package to support token retrieval (ASG-2921)
* feat: New method to remove group from user permit (ASG-2921)

## v1.0.34

* feat: Add exempt from expiring functionality (ASG-3055)

## v1.0.33

* fix: Update to Go118

Technically this is not an API change, so we don't have to create a new version,
but we want to officially release a new version if the binaries could be
different - because the build process is different.

## v1.0.32

* feat: Add map lookup for AuthUserType names (ASG-2921)

## v1.0.31

* fix: Auth fails if a group is not found in a user permit. (ASG-1990)
* fix: Patch vulnerabilities in golang.org/x/crypto

## v1.0.30

* fix: ASG-2690: Enhance OAuth logging

## v1.0.29

* fix: ASG-2622: Change all msaad logs to *info*.

## v1.0.28

* fix: Set Email and Username variables on the Token in CreateSession()

## v1.0.27

* fix: Add authuserstore db triggers. (ASG-2210)

Introduced db triggers for the public.authuserstore db table within the auth db.

These triggers will enforce the following.

`created (timestamp)` will now be set to NOW() on creation of a record by the
trigger itself.  
`created` can also now not be modified on an update.  
`modified (timestamp)` will now be set to NOW() on creation and record update by
the trigger itself.  
`createdby (int)` is now a mandatory field and the trigger wil raise in exception
if it is not provided.  
`createdby` can also not be modified on any subsequent update.

## v1.0.26

* fix: passthrough auth session bug. (BAZ-202)

## v1.0.25

* Modified the MSAAD synchronisation process to set blank usernames for users in Auth to the email provided from AD.
 
## v1.0.24

* Deprecated