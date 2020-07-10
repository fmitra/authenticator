# authenticator

A generic user authentication service supporting FIDO U2F, TOTP, Email, and SMS.

## Overview

Account management is one of the more boring and yet necessary portions of most user
facing systems. Here we attempt to provide some sane, secure defaults so you can
focus on building your product instead.

For an overview of the API, refer to the [documentation here](docs/api_v1.md)

For an example clientside implementation of some of the core API's provided here,
refer to the [client repository](https://github.com/fmitra/authenticator-client)

### Authentication Tokens

[JWT tokens](https://jwt.io) are used for authentication. Their stateless nature allows
us to check verification without managing a session in a database. Additionally signed
tokens provide data integrity, providing our other applications a degree of trust
with the user identity information contained within it.

JWT Tokens are embeded with a fingerprint, which we refer to here as a `client ID` to help prevent [token sidejacking](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking).

JWT Tokens are short lived by default (20 minutes) but may be refreshed after expiry
with a valid `refresh token`. Refresh tokens have their own, configurable long lived expiry time
(15 days by default) and set on the client securely along side the client ID.

### Passwordless Authentication

Passwordless authentication is planned as an optional system wide configuration. It is often used
to ease onboarding flows. Popular examples can be seen by popular start ups such as
Uber, Grab, and Square Cash.  We support this this as we [can argue](https://auth0.com/passwordless) that randomly
generated, time sensitive multi-character codes are oftentimes more secure then common
user generated passwords and mitigates password reuse.

### Registration

Registration requires either a phone number or email address as it is a requirement to
verify the authenticity of a user. The service may be required to enforce email only
registration, phone only, or a combination of both.

### Authentication and 2FA

Authentication requires a password (unless passwordless authentication is enabled) and
an assertion of identity. The assertion may be one of the following 2FA methods:

* **OTP**: A one time password (by default, a 6 digit code) will be delivered to the
user's email address or phone number. This is the default setting and may be disabled
after the user enables an alternative 2FA method.

* **TOTP**: Users may generate a time based one time password through a supported
application.

* **FIDO** Users may submit a signed WebAuthn challenge to authenticate with any standard
FIDO device (e.g. MacOS fingerprint reader, YubiKey)

### Client Flow/Storage

While secure cookie storage is available on web browsers, tokens are instead expected
to be stored in either LocalStorage or SessionStorage (or some secure storage in a native
mobile app). This ensure clients have access to the token to retrieve basic information
about the user's idenitty. To authenticate, clients are expected to create an authentication
header and pass their tokens with a `Bearer` prefix. This eliminates the complexity of
additionally supporting CSRF tokens.

To mitigate XSS attacks targeted at token storages, tokens are fingerprinted with a random
string's hash. The hash value (the `client ID`) should be securely stored on the client. After
authentication, the client ID is set as a secure cookie on the browser. It is additionally
available as part of the response payload so mobile clients can store it themselves.

### Revocation

Token revocation is an inherit problem with JWT tokens as revocation relies on an expiry
date. In order to accomplish revocation without a session store, we instead maintain a [blacklist](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#blacklist-storage).

Tokens are blacklisted in a fast storage (here Redis is used) and removed upon expiry.

### Auditability

Records for login history are created upon each successful login and associated with a
JWT token ID. This history allows us to provide users a way audit their account and
revoke tokens. After revocations, tokens may no longer refresh and the user must login in
again to retrieve a new JWT token and accompanying refresh token.

### Design Rationale

**Token storage**: We avoid setting authentication tokens to cookies to avoid the need to
provide CSRF token support and allow us to rely solely on the contents of a JWT token
for authenticaiton. [Fingerprinting](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#how-to-prevent_1) the token with a securely stored value is instead
used to mitigate risks of XSS attacks that may occur by allowing clients to save their
tokens in other storages.

**2FA**: 2FA delivery via email and SMS is disabled after User's enable a TOTP
appicaiton or a FIDO U2F key as the secondary delivery method provides a less
secure fallback. We expect users to be aware of the pros/cons of enabling
additional security methods and do not penalize them by offering a fallback.

**SRP**: [SRP](https://github.com/fmitra/srp) is an authentication protocol to mitigate MITM attacks.
It was left out as an authentication protocol for this service as it would add significant
complexity to client side auth flow  and competes with building adoption for WebAuthn.

## Pending

Following features are still being planned out

* Password reset
* Passwordless authentication
* Retrieval of login history and old JWT token IDs
* Retrieval of registered FIDO devices

## Development

For a default development set up:

**Generate default config**

```
make dev
```

**Start Postgres and Redis**

```
docker-compose up -d
```

**Build and run the project**

```
go build ./cmd/api
./api --config=./config.json
```

**Test and lint the project**

Make sure [golangci-lint](https://golangci-lint.run/usage/install/) is installed prior to running the linter.

```
make test
make lint
```

## Alternatives

* [Auth0](https://auth0.com/) Packages authentication as a service but results in leaving
your user account management up to an external third party which may not be feasible
for some compliance or business needs. It's free plan provides limited support and paid
plans are arguably expensive for several thousands of users.

* [AuthRocket](https://authrocket.com) Provides similar features to Auth0. The service
is less mature than it's competitor and more expensive at low tier plans.

## References

* [JWT Token Revokation](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#no-built-in-token-revocation-by-the-user)

* [Token Sidejacking](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking)

* [Passwordless Authentication](https://auth0.com/passwordless)

* [Token refresh](https://auth0.com/learn/refresh-tokens)
