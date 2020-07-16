/*
Package Authaus is an authentication and authorization system.

Authaus brings together the following pluggable components:

	Authenticator           This simply answers the question "Is this username/password valid?"
	Session Database        This stores session keys and associated tokens (aka cookies).
	Permit Database         This is where you store the permits (aka permissions granted).
	Role Groups Database    This knows how to interpret a permit, and turn it into a list of roles.
	User Store    			This is where we store user details, such as email address, contact details, name, surname etc.

Any of these five components can be swapped out, and in fact the fourth, and fifth ones (Role Groups and User Store) are entirely optional.

A typical setup is to use LDAP as an Authenticator, and Postgres as a Session, Permit, and Role Groups database.

Your session database does not need to be particularly performant, since Authaus maintains
an in-process cache of session keys and their associated tokens.

Intended Usage

Authaus was NOT designed to be a "Facebook Scale" system. The target audience is a system
of perhaps 100,000 users. There is nothing fundamentally limiting about the API of Authaus,
but the internals certainly have not been built with millions of users in mind.

The intended usage model is this:

Authaus is intended to be embedded inside your security system, and run as a standalone HTTP
service (aka a REST service).
This HTTP service CAN be open to the wide world, but it's also completely OK to let it listen
only to servers inside your DMZ. Authaus only gives you the skeleton and some examples of HTTP responders.
It's up to you to flesh out the details of your authentication HTTP interface,
and whether you'd like that to face the world, or whether it should only be
accessible via other services that you control.

At startup, your services open an HTTP connection to the Authaus service. This connection
will typically live for the duration of the service. For every incoming request, you peel off whatever
authentication information is associated with that request. This is either a session key,
or a username/password combination. Let's call it the authorization information. You then ask
Authaus to tell you WHO this authorization information belongs to, as well as WHAT this
authorization information allows the requester to do (ie Authentication and Authorization).
Authaus responds either with a 401 (Unauthorized), 403 (Forbidden), or a 200 (OK) and a JSON object
that tells you the identity of the agent submitting this request, as well the permissions
that this agent posesses. It's up to your individual services to decide what to do with that
information.

It should be very easy to expose Authaus over a protocol other than HTTP, since Authaus is
intended to be easy to embed. The HTTP API is merely an illustrative example.

Concepts

A `Session Key` is the long random number that is typically stored as a cookie.

A `Permit` is a set of roles that has been granted to a user. Authaus knows nothing about
the contents of a permit. It simply treats it as a binary blob, and when writing it to
an SQL database, encodes it as base64. The interpretation of the permit is application
dependent. Typically, a Permit will hold information such as "Allowed to view billing information",
or "Allowed to paint your bathroom yellow". Authaus does have a built-in module called
RoleGroupDB, which has its own interpretation of what a Permit is, but you do not need to use this.

A `Token` is the result of a successful authentication. It stores the identity of a user,
an expiry date, and a Permit. A token will usually be retrieved by a session key.
However, you can also perform a once-off authentication, which also yields you a token,
which you will typically throw away when you are finished with it.

Concurrency

All public methods of the `Central` object are callable from multiple threads. Reader-Writer
locks are used in all of the caching systems.

The number of concurrent connections is limited only by the limits of the Go runtime, and the
performance limits that are inherent to the simple reader-writer locks used to protect shared state.

Deployment

Authaus must be deployed as a single process (which implies running on a single logical
machine). The sole reason why it must run on only one process and not more, is because
of the state that lives inside the various Authaus caches. Were it not for these caches,
then there would be nothing preventing you from running Authaus on as many
machines as necessary.

The cached state stored inside the Authaus server is:

	* Cached Session Database
	* Cached Role Group Database

If you wanted to make Authaus runnable across multiple processes, then you would need
to implement a cache invalidation system for these caches.

DOS Attacks

Authaus makes no attempt to mitigate DOS attacks. The most sane approach in this
domain seems to be this
(http://security.stackexchange.com/questions/12101/prevent-denial-of-service-attacks-against-slow-hashing-functions).

Crypto

The password database (created via NewAuthenticationDB_SQL) stores password hashes
using the scrypt key derivation system (http://www.tarsnap.com/scrypt.html).

Internally, we store our hash in a format that can later be extended, should we
wish to double-hash the passwords, etc.
The hash is 65 bytes and looks like this:
	Bytes                1        32     32     (sum = 65 bytes)
	Information       Version    Salt   Hash
The first
byte of the hash is a version number of the hash. The remaining 64 bytes are the
salt and the hash itself. At present, only one version is
supported, which is version 1. It consists of 32 bytes of salt, and 32 bytes of
scrypt'ed hash, with scrypt parameters N=256 r=8 p=1. Note that the parameter N=256
is quite low, meaning that it is possible to compute this in approximately 1 millisecond
(1,000,000 nanoseconds) on a 2009-era Intel Core i7. This is a deliberate tradeoff.
On the same CPU, a SHA256 hash takes about 500 nanoseconds to compute, so we are
still making it 2000 times harder to brute force the passwords than an equivalent
system storing only a SHA256 salted hash. This discussion is only of relevance
in the event that the password table is compromised.

No cookie signing mechanism is implemented.

Cookies are not presently transmitted with Secure:true. This must change.

LDAP Authenticator

The LDAP Authenticator is extremely simple, and provides only one function: Authenticate
a user against an LDAP system (often this means Active Directory, AKA a Windows Domain).

It calls the LDAP "Bind" method, and if that succeeds for the given identity/password,
then the user is considered authenticated.

We take care not to allow an "anonymous bind",
which many LDAP servers allow when the password is blank.

Session Database

The Session Database runs on Postgres. It stores a table of sessions, where each row
contains the following information:

	* A session key (aka the cookie's "Value")
	* The identity that created that session
	* The cached permit of that identity
	* When the session expires

When a permit is altered with Authaus, then all existing sessions have their permits
altered transparently. For example, imagine User X is logged in, and his administrator grants
him a new permission. User X does not need to log out and log back in again in order for
his new permissions to be reflected. His new permissions will be available immediately.

Similarly, if a password is changed with Authaus, then all sessions are invalidated. Do take
note though, that if a password is changed through an external mechanism (such as with LDAP),
then Authaus will have no way of knowing this, and will continue to serve up sessions
that were authenticated with the old password. This is a problem that needs addressing.

You can limit the number of concurrent sessions per user to 1, by setting
MaxActiveSessions.ConfigSessionDB to 1. This setting may only be zero or one. Zero, which is
the default, means an unlimited number of concurrent sessions per user.

Session Cache

Authaus will always place your Session Database behind its own Session Cache. This session
cache is a very simple single-process in-memory cache of recent sessions. The limit
on the number of entries in this cache is hard-coded, and that should probably change.

Permit Database

The Permit database runs on Postgres. It stores a table of permits, which is simply
a 1:1 mapping from Identity -> Permit. The Permit is just an array of bytes, which
we store base64 encoded, inside a text field. This part of the system doesn't care how you
interpret that blob.

Role Group Database

The Role Group Database is an entirely optional component of Authaus. The other components
of Authaus (Authenticator, PermitDB, SessionDB) do not understand your Permits. To them,
a Permit is simply an arbitrary array of bytes.

The Role Group Database is a component that adds a specific meaning to a permit blob. Let's
see what that specific meaning looks like...

The built-in Role Group Database interprets a permit blob as a string of 32-bit integer IDs:

	// A permit with 3 "role groups"
	0x000000bc 0x00000001 0x000000fe

These 32-bit integer IDs refer to "role groups" inside a database table. The "role groups"
table might look like this:

	------------------------------------
	Role Groups Table
	------------------------------------
	ID              Roles
	0x00000001      0x00ab 0x00aa 0x0001
	0x000000bc      0x00b0
	0x000000fe      0x00b0 0x00bf 0x0001

The Role Group IDs use 32-bit indices, because we assume that you are not going to
create more than 2^32 different role groups. The worst case we assume here is that
of an automated system that creates 100,000 roles per day. Such a system would run
for more than 100 years, given a 32-bit ID. These constraints are extraordinary,
suggesting that we do not even need 32 bits, but could even get away with just a
16-bit group ID.

However, we expect the number of groups to be relatively small. Our aim here, arbitrary
though it may be, is to fit the permit and identity into a single ethernet packet,
which one can reasonably peg at 1500 bytes. 1500 / 4 = 375. We assume that no sane human
administrator will assign 375 security groups to any individual. We expect the number of groups
assigned to any individual to be in the range of 1 to 20. This makes 375 a gigantic
buffer.

OAuth

OAuth support in Authaus is limited to a very simple scenario:

* You wish to allow your users to login using an OAuth service - thereby outsourcing the
Authentication to that external service, and using it to populate the email address of
your users.

OAuth was developed in order to work with Microsoft Azure Active Directory, however
it should be fairly easy to extend the code to be able to handle other OAuth providers.

Inside the database are two tables related to OAuth:

oauthchallenge: The challenge table holds OAuth sessions which have been started, and which are expected to either
succeed or fail within the next few minutes. The default timeout for a challenge is 5 minutes.
A challenge record is usually created the moment the user clicks on the "Sign in with Microsoft" button
on your site, and it tracks that authentication attempt.

oauthsession: The session table holds OAuth sessions which have successfully authenticated, and also
the token that was retrieved by a successful authorization. If a token has expired, then it is refreshed
and updated in-place, inside the oauthsession table.

An OAuth login follows this sequence of events:

1. User clicks on a "Signin with X" button on your login page
2. A record is created in the oauthchallenge table, with a unique ID. This ID is a secret known
only to the authaus server and the OAuth server. It is used as the `state` parameter in the OAuth
login mechanism.
3. The HTTP call which prompts #2 return a redirect URL (eg via an HTTP 302 response), which redirects
the user's browser to the OAuth website, so that the user can either grant or refuse access. If the
user refuses, or fails to login, then the login sequence ends here.
4. Upon successful authorization with the OAuth system, the OAuth website redirects the user back to
your website, to a URL such as example.com/auth/oauth/finish, and you'll typically want Authaus to
handle this request directly (via HttpHandlerOAuthFinish). Authaus will extract the secrets from
the URL, perform any validations necessary, and then move the record from the oauthchallenge table,
into the oauthsession table. While 'moving' the record over, it will also add any additional
information that was provided by the successful authentication, such as the token provided by the
OAuth provider.
5. Authaus makes an API call to the OAuth system, to retrieve the email address and name of the
person that just logged in, using the token just received.
6. If that email address does not exist inside authuserstore, then create a new user record
for this identity.
7. Log the user into Authaus, by creating a record inside authsession, for the relevant identity.
Inside the authsession table, store a link to the oauthsession record, so that there is a 1:1
link from the authsession table, to the oauthsession table (ie Authaus Session to OAuth Token).
8. Return an Authaus session cookie to the browser, thereby completing the login.

Although we only use our OAuth token a single time, during login, to retrieve the user's
email address and name, we retain the OAuth token, and so we maintain the ability to make
other API calls on behalf of that user. This hasn't proven necessary yet, but it seems like
a reasonable bit of future-proofing.

Testing

See the guidelines at the top of all_test.go for testing instructions.

*/
package authaus
