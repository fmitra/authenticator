# authenticator

A generic user authentication service supporting FIDO U2F, TOTP, Email, and SMS.

## Contents

* [Overview](#overview)

  * [Authentication Tokens](#authentication-tokens)
  * [Passwordless Authentication](#passwordless-authentication)
  * [Registration](#registration)
  * [Authentication and 2FA](#authentication)
  * [Client Flow/Storage](#client)
  * [Revocation/Invalidation](#revocation)
  * [Auditability](#auditability)
  * [Design Rationale](#rationale)

* [Development](#development)

  * [Getting Started](#getting-started)
  * [Test and Lint](#test-and-lint)
  * [Load Testing](#load-testing)

* [Performance](#performance)
* [Alternatives](#alternatives)
* [References](#references)
* [Pending](#pending)

## <a name="overview">Overview</a>

Account management is one of the more boring and yet necessary portions of most user
facing systems. Here we attempt to provide some sane, secure defaults so you can
focus on building your product instead.

For an overview of the API, refer to the [documentation here](docs/api_v1.md)

For an example clientside implementation of some of the core API's provided here,
refer to the [client repository](https://github.com/fmitra/authenticator-client)

### <a name="authentication-tokens">Authentication Tokens</a>

[JWT tokens](https://jwt.io) are used for authentication. Their stateless nature allows
us to check verification without managing a session in a database. Additionally signed
tokens provide data integrity, providing our other applications a degree of trust
with the user identity information contained within it.

JWT Tokens are embeded with a fingerprint, which we refer to here as a `client ID` to help prevent [token sidejacking](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking).

JWT Tokens are short lived by default (20 minutes) but may be refreshed after expiry
with a valid `refresh token`. Refresh tokens have their own, configurable long lived expiry time
(15 days by default) and set on the client securely along side the client ID.

### <a name="passwordless-authentication">Passwordless Authentication</a>

Passwordless authentication is **planned** as an optional system wide configuration. It is often used
to ease onboarding flows. Popular examples can be seen by popular start ups such as
Uber, Grab, and Square Cash.  We support this this as we [can argue](https://auth0.com/passwordless) that randomly
generated, time sensitive multi-character codes are oftentimes more secure then common
user generated passwords and mitigates password reuse.

### <a name="registration">Registration</a>

Registration requires either a phone number or email address as it is a requirement to
verify the authenticity of a user. The service may be required to enforce email only
registration, phone only, or a combination of both.

### <a name="authentication">Authentication and 2FA</a>

Authentication requires a password (unless passwordless authentication is enabled) and
an assertion of identity. The assertion may be one of the following 2FA methods:

* **OTP**: A one time password (by default, a 6 digit code) will be delivered to the
user's email address or phone number. This is the default setting and may be disabled
after the user enables an alternative 2FA method.

* **TOTP**: Users may generate a time based one time password through a supported
application.

* **FIDO** Users may submit a signed WebAuthn challenge to authenticate with any standard
FIDO device (e.g. MacOS fingerprint reader, YubiKey)

### <a name="client">Client Flow/Storage</a>

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

### <a name="revocation">Revocation and Invalidation</a>

Older tokens may be explicitly revoked by a user or automatically invalidated by us
(for example, when refreshing a token). Handling this is an inherent problem with
JWT tokens as revocation typlically relies on setting a short enough expiry period
for service owners to consider the risk minimal. This allows us to make use of one
of the major benefits of JWT tokens by allowing simple validation without a session store.

For this project, I've opted to take the middle ground and support revocation using
a fast storage (here Redis is used) and maintaing a [blacklist](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#blacklist-storage) of Token IDs.

### <a name="auditability">Auditability</a>

Records for login history are created upon each successful login and associated with a
JWT token ID. This history allows us to provide users a way audit their account and
revoke tokens. After revocations, tokens may no longer refresh and the user must login in
again to retrieve a new JWT token and accompanying refresh token.

### <a name="rationale">Design Rationale</a>

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

## <a name="development">Development</a>

### <a name="getting-started">Getting Started</a>

**1. Generate default config**

`config.json` and a corresponding `docker-compose.yml` file will be created. It assumes
you intend to run the client and backend on `authenticator.local`.

```
cd authenticator
make dev
```

**2. Start the project and dependencies**

By default the project will be exposed on port `8081`.

```
cd authenticator
docker-compose up -d
```

You can check the project is up and running via the healthcheck endpoint

```
curl http://localhost:8081/healthcheck
```

If you would like to build and run the project without docker, you can compile
the binary directly and pass the location of your configuration file:

```
go build ./cmd/api
./api --config=./config.json
```

**3. Setup database**

If this is your first time running the project, you'll need to set up the initial
DB schema found in [schema.go](./schema.go).

```
docker-compose exec postgres psql -U auth -d authenticator_test
```

### <a name="test-and-lint">Test and Lint</a>

Make sure [golangci-lint](https://golangci-lint.run/usage/install/) is installed prior to running the linter.

```
make test
make lint
```

### <a name="load-testing">Load Testing</a>

[Artillery.io](https://artillery.io/docs/) is used for load testing. In depth tests
are not set up yet but we can get a general idea of performance on [token validation](./loadtest/token-verify.yml)
with a Redis backed throttle.

First install Artillery ([Node.js](https://nodejs.org) is a prerequisite)

```
npm install -g artillery
artillery -V
```

Set the target domain and run the tests.

```
export AUTHENTICATOR_DOMAIN=http://138.65.75.135
artillery run loadtest/token-verify.yml
```

## <a name="performance">Performance</a>

An indepth review has not been completed yet. Although an initial test on a *Digital Ocean
droplet $5 droplet (1GB/1CPU, 25GB SSD) with PostgreSQL and Redis running together on the same
instance* shows we can reasonably expect handle around `200` concurrent users per second while
maintaining a response time of around `300ms` for end users for 95% of requests on the
single DO instance.

Ramping up to `800` concurrent users per second on the same DO instance over a 7 minute period
shows degregation in response times to `500ms` for 95% of requests with a `0.004%` error rate.

Example report overview:

* Server: Digital Ocean (1GB/1CPU, 25GB SSD)
* Server Location: New York
* Load Test Client Location: New York
* Environment: Application, PostgreSQL, Redis, running dockerized on the single instance
* Conditions: Maximum 800req/sec, average 167req/sec over 7 minutes

Report: Average 5req/sec

```
Report @ 14:43:47(-0400) 2020-08-07
Elapsed time: 1 minute, 10 seconds
  Scenarios launched:  56
  Scenarios completed: 56
  Requests completed:  56
  Mean response/sec: 5.61
  Response time (msec):
    min: 252.3
    max: 288.3
    median: 267.8
    p95: 283.9
    p99: 288.3
  Codes:
    401: 10
    429: 46
```

Report: Average 200req/sec

```
Report @ 14:59:38(-0400) 2020-08-07
Elapsed time: 5 minutes, 20 seconds
  Scenarios launched:  2430
  Scenarios completed: 2420
  Requests completed:  2420
  Mean response/sec: 243.34
  Response time (msec):
    min: 253.3
    max: 1729.4
    median: 278.9
    p95: 320.3
    p99: 727.5
  Codes:
    401: 10
    429: 2410
```

Report: Request ramp to 800req/sec

```
Report @ 15:01:18(-0400) 2020-08-07
Elapsed time: 7 minutes, 0 seconds
  Scenarios launched:  7045
  Scenarios completed: 7009
  Requests completed:  7009
  Mean response/sec: 705.91
  Response time (msec):
    min: 266.4
    max: 3362.7
    median: 359.3
    p95: 507.6
    p99: 1585.1
  Codes:
    401: 10
    429: 6999
```

Report: Summary

```
Summary report @ 15:01:23(-0400) 2020-08-07
  Scenarios launched:  71063
  Scenarios completed: 71060
  Requests completed:  71060
  Mean response/sec: 167.23
  Response time (msec):
    min: 250.1
    max: 4032.2
    median: 296.2
    p95: 496.3
    p99: 1529.3
  Scenario counts:
    0: 71063 (100%)
  Codes:
    401: 425
    429: 70635
  Errors:
    ECONNRESET: 3
```

## <a name="alternatives">Alternatives</a>

* [Auth0](https://auth0.com/) Packages authentication as a service but results in leaving
your user account management up to an external third party which may not be feasible
for some compliance or business needs. It's free plan provides limited support and paid
plans are arguably expensive for several thousands of users.

* [AuthRocket](https://authrocket.com) Provides similar features to Auth0. The service
is less mature than it's competitor and more expensive at low tier plans.

## <a name="references">References</a>

* [JWT Token Revokation](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#no-built-in-token-revocation-by-the-user)

* [Token Sidejacking](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking)

* [Passwordless Authentication](https://auth0.com/passwordless)

* [Token refresh](https://auth0.com/learn/refresh-tokens)

## <a name="pending">Pending</a>

Following features are still being planned out

* Password reset
* Passwordless authentication
* Retrieval of login history
