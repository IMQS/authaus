# Changelog

## current

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