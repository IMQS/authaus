# Changelog

## current

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

## v1.0.26

* fix: passthrough auth session bug. (BAZ-202)

## v1.0.25

* Modified the MSAAD synchronisation process to set blank usernames for users in Auth to the email provided from AD.
 
## v1.0.24

* Deprecated