/*
Package Authaus is an authentication and authorization system.

Authaus brings together the following pluggable components:

	Authenticator		This simply answers the question "Is this username/password valid?"
	Session Database	This stores login tokens. In other words, this is where the cookies go.
	Permit Database		This is where you store the permits (aka permissions granted).

Any of these three components can be swapped out.

A typical setup is to use LDAP as an Authenticator, and Postgres as a Session Database and Permit Database.

Your session database does not need to be particularly performant, since Authaus maintains
an in-process cache of session tokens.

Concepts

A Permit is a set of roles that has been granted to a user.

A Token is the result of a successful authentication. It stores the identity of a user,
an expiry date, and a Permit. A token will usually be retrieved by a session key.
However, you can also perform a once-off authentication, which also yields you a token,
which you will typically throw away when you are finished with it.

*/
package authaus
