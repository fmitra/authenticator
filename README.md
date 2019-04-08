# authenticator

A generic user authentication micro-service supporting Email/SMS, TOTP, FIDO U2F and WebAuthn.

## Overview

Account management is one of the more boring and yet necessary portions of most user
facing systems. Authenticator attempts to provide some sane, secure defaults so you can
focus on building your product instead.

### Authentication Tokens

[JWT tokens](https://jwt.io) are used for authentication. Their stateless nature allows
us to check verification without managing a session in a database. Additionally signed
tokens provide data integrity, providing our other applications a degree of trust
with the user identity information contained within it.

Tokens are embeded with a fingerprint to help prevent [token sidejacking](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking).

### Registration

Registration requires either a phone number or email address as it is a requirement to
verify the authenticity of a user. The service may be required to enforce email only
registatraion, phone only, or a combination of both.

New registrations are required to complete verify their accounts with a one time passcode.

### Passwordless Authentication

Passwordless authentication is an optional system wide configuration. It is often used
to ease onboarding flows. Popular examples can be seen by popular start ups such as
Uber, Grab, and Square Cash.  We support this this as we [can argue](https://auth0.com/passwordless) that randomly
generated, time sensitive multi-character codes are oftentimes more secure then common
user generated passwords and mitigates password reuse.

### Multi Factor Authentication

Email and SMS may be configured on a per-user basis to be used as 2FA method.

Additionally if a TOTP application or FIDO U2F key is enabled on the account, 2FA
delivery via email and SMS will be disabled.

### Client Flow/Storage

While secure cookie storage is available on web browsers, tokens are instead expected
to be stored in either LocalStorage or SessionStorage (or secure storage in a native
mobile app). Clients are expected to create an authentication header and pass their tokens
with a `Bearer` prefix. This eliminates the complexity of additionally supporting CSRF
tokens.

To mitigate XSS attacks targeted at token storages, tokens are fingerprinted with a random
string's hash. The hash value is securely stored in the (secure cookie storage in the
case of the browser) and sent along with the token for validation.

### Revocation

Token revocation is an inherit problem with JWT tokens as revocation relies on an expiry
date. In order to accomplish revocation without a session store, we instead maintain a [blacklist](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-explicit-revocation-by-the-user).

Tokens are blacklisted in a fast storage (here Redis is used) and removed upon expiry.

### Auditability

Records for login history are created upon each successful login and associated with a
JWT token ID. This history allows us to provide users a way audit their account and
revoke tokens.

### Design Rationale

**Token storage**: We avoid setting authentication tokens to cookies to avoid the need to
provide CSRF token support and allow us to rely solely on the contents of a JWT token
for authenticaiton. Fingerprinting the token with a securely stored value is instead
used to mitigate risks of XSS attacks that may occur by allowing clients to save their
tokens in other storages.

**2FA**: 2FA delivery via email and SMS is disabled after User's enable a TOTP
appicaiton or a FIDO U2F key as the secondary delivery method provides a less
secure fallback. We expect users to be aware of the pros/cons of enabling
additional security methods and do not penalize them by offering a fallback.

**SRP**: [SRP](https://github.com/fmitra/srp) is an authentication protocol to mitigate MITM attacks.
It was left out as an authentication protocol for this service as it would add significant
complexity to client side auth flow  and competes with building adoption for WebAuthn.

## Open Topics

Following issues are still under consideration

* Password reset flow
* Token expiry time and refresh flow
* Per-user configuration

## Alternatives

* [Auth0](https://auth0.com/) Packages authentication as a service but results in leaving
your user account management up to an external third party which may not be feasible
for some compliance or business needs. It's free plan provides limited support and paid
plans are arguably expensive for several thousands of users.

* [AuthRocket](https://authrocket.com) Provides similar features to Auth0. The service
is less mature than it's competitor and more expensive at low tier plans.

## References

* [JWT Token Revokation](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-explicit-revocation-by-the-user)

* [Token Sidejacking](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking)

* [Passwordless Authentication](https://auth0.com/passwordless)
