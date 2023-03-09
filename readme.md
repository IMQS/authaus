Authaus
=======

2023-03-06

Introduced db triggers for the public.authuserstore db table within the auth db.

These triggers will enforce the following. 

created (timestamp) will now be set to NOW() on creation of a record by the trigger itself. created can also now not be modified on an update. 
modified (timestamp) will now be set to NOW() on creation and and record update by the trigger itself.
createdby (int) is now a mandatory field and the trigger wil raise in exception if it is not provided. createdby can also not be modified on any subsequent update. 

Authaus is an authentication and authorization system written in Go.
See the [documentation](http://godoc.org/github.com/IMQS/authaus) for more information.

v1.0.25 Modified the MSAAD synchronisation process to set blank usernames for users in Auth to the email provided from AD.
 
v1.0.24 Deprecated
