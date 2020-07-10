# Authenticator API

## Contents

* [Overview](#overview)

  * [JWT Token](#overview-jwt)
  * [Client ID](#overview-client-id)
  * [Refresh Token](#overview-refresh-token)

* [Sign Up API](#signup-api)

  * [Initate registration](#initiate-registration)
  * [Verify registration](#verify-registration)

* [Login API](#login-api)

  * [Initiate login](#initiate-login)
  * [Login with code](#login-with-code)
  * [Login with device](#login-with-device)
  * [Request device challenge](#request-device-challenge)

* [Device API](#device-api)

  * [Initiate device registration](#initiate-device)
  * [Verify device](#verify-device)
  * [Remove device](#remove-device)

* [Token API](#token-api)

  * [Revoke token](#token-revoke)
  * [Verify token](#token-verify)
  * [Refresh token](#token-refresh)

* [TOTP API](#totp-api)

  * [Generate TOTP secret](#totp-secret)
  * [Enable TOTP](#enable-totp)
  * [Disable TOTP](#disable-totp)

* [Contact API](#contact-api)

  * [Request address update](#request-address-update)
  * [Disable address](#disable-address)
  * [Verify address](#verify-address)
  * [Remove address](#remove-address)
  * [Resend OTP to address](#resend-otp)

## <a name="overview">Overview</a>

This document details all available HTTP API endpoints exposed by the service to manage
JWT tokens.

### <a name="overview-jwt">JWT Token</a>

JWT tokens assert the User's identity and status as an authorized user and my be received
in 2 states: `authorized` or `pre_authorized`

* `authorized` - User is fully authenticated and has completed 2FA
* `pre_authroized` - User has been identified via their email or phone number, but has yet complete 2FA authentication

JWT tokens are short lived but may be refreshed with a refresh token. They have the following properties:

| Property | Description |
| -------- | ----------- |
| client_id | The hash of a JWT Token's accompanying client ID |
| user_id | Unique ID (ULID) of the User. This value will not change |
| email | Email address of the User. This value may be modified |
| phone | Phone number of the User. This value may be modified |
| state | State of the user in our system, either `authorized` or `pre_authorized` (pending 2FA) |
| refresh_token | The hash of a JWT Token's accompanying refresh token |
| tfa_options | A list of available 2FA options for the client to render for a user (`phone`, `email`, `device`) |
| expires_at | The latest validity time of a token as a unix timestamps. Expired tokens may be refreshed |

#### Authentication with JWT

Clients are expected to deliver the JWT token through the following header:

```
Authorization: Bearer <jwtToken>
```

In addition to the JWT token, the client ID is also expected to be sent back in a cookie
header to verify the user.

### <a name="overview-client-id">Client ID</a>

To mitigate XSS attacks, tokens are fingerprinted with the hash value of a client ID. The client ID
is expected to be store securely on the client (e.g. HTTP Only, Secure Only cookie) and returned
back to us in a cookie header. If a client ID is not provided, authentication will fail.

Client IDs are only provided to a user after signup/login. Other endpoints will refresh
a token and therefore share the same client ID.

```
Cookie: CLIENTID=<clientID>
```

### <a name="overview-refresh-token">Refresh Token</a>

Refresh tokens are long lived tokens that allow a user to refresh a non-revoked JWT token.
Refresh tokens are supplied to a user after successful authentication alongside a client ID
and are expected to be returned back in a cookie header to refresh a token.

New refresh tokens may only be retrieved from a successful login.

```
Cookie: REFRESHTOKEN=<refreshToken>
```

## <a name="signup-api">SignUp API</a>

Provides endpoints to manage user registration. It is a 2-step API and a pre-requisite
in order to obtain a authentication token to access protected resources.

A client initiates registration with a POST request to `api/v1/signup` and completes
registration with a subsequent POST request to `api/v1/signup/verify` in which they
validate a response we return to them from their initial request.

### <a name="initiate-registration">Initiate registration [POST /api/v1/signup]</a>

A user provides either an email or phone number for us to tidentify them. On success
we will send a random code to their contact address and a JWT token with status `unverified`.

* Request (application/json)

  * Parameters

      * type (required, string) - Description of idenitty, either `email` or `phone`
      * identity (required, string) - Phone number or email address of the user.
      * password (required, string) - Password of the user.

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "TSF9SUpSdj8rQmcpXTc9VX1VUzQtVC96fVdBZ0lKIXxdKycvVGNVMw"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "invalid_field",
    "message": "Email address is invalid"
  }
}
```

### <a name="verify-registration">Verify registration [POST /api/v1/signup/verify]</a>

A user proves their identity to us by sending back the randomly generated code we
delivered to them. On success they will receive a JWT token asserting their status
as a new `authorized` user.

* Request (application/json)

  * Parameters

      * code (required, string) - 6 digit code sent to user.

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "TSF9SUpSdj8rQmcpXTc9VX1VUzQtVC96fVdBZ0lKIXxdKycvVGNVMw",
  "refreshToken:" "eyJjb2RlIjoiWCxMN2Q2LWA6JzJcdTAwM2UhenFNb1FcImJaZlFLUyRwOGRPWj1bamBAZm9BXHUwMDNlIiwiZXhwaXJlc19hdCI6MTU5NDQwNTc1MX0",
}
```
* Response 400 (application/json)

```json
{
  "error": {
    "code": "invalid_code",
    "message": "incorrect code provided"
  }
}
```

## <a name="login-api">Login API</a>

Provides endpoints to manage user authentication. It is a 2-step API where a client
initiates login with a POST request to `api/v1/login`. After the initial request, they
will complete the multi-factor authentication requirement with a POST request to either
`api/v1/login/device` or `api/v1/login/code` to verify a device, randomly generated
code or TOTP code.

### <a name="initiate-login">Initiate login [POST /api/v1/login]</a>

A user provides either an email or phone number and password for us to identify them.
On success we will return a JWT token with state `pre_authorized`.

* Request (application/json)

  * Parameters

      * type (required, string) - Description of idenitty, either `email` or `phone`
      * identity (required, string) - Phone number or email address of the user.
      * password (required, string) - Password of the user.

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "TSF9SUpSdj8rQmcpXTc9VX1VUzQtVC96fVdBZ0lKIXxdKycvVGNVMw"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "invalid_field",
    "message": "Email address is invalid"
  }
}
```

### <a name="login-with-code">Complete login with code [POST /api/v1/login/verify-code]</a>

A user submits a random server generated code or TOTP code. On success we will return
a JWT token with state `authorized`.

* Request (application/json)

  * Parameters

      * code (required, string) - 6 digit code sent to user.

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "TSF9SUpSdj8rQmcpXTc9VX1VUzQtVC96fVdBZ0lKIXxdKycvVGNVMw",
  "refreshToken:" "eyJjb2RlIjoiWCxMN2Q2LWA6JzJcdTAwM2UhenFNb1FcImJaZlFLUyRwOGRPWj1bamBAZm9BXHUwMDNlIiwiZXhwaXJlc19hdCI6MTU5NDQwNTc1MX0",
}
```
* Response 400 (application/json)

```json
{
  "error": {
    "code": "invalid_code",
    "message": "incorrect code provided"
  }
}
```

### <a name="login-with-device">Complete login with device [POST /api/v1/login/verify-device]</a>

A user signs a server challenge with their WebAuthn capable device. On success we will
return a JWT token with status `authorized`.

* Request (application/json)

  * Parameters

      * id (required, string) - `id` generated from browser's navigator.credentials.create API
      * rawId (required, string) - `rawId` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
      * response (required, object)
          * attestationObject (required, string) - `attestationObject` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
          * clientDataJSON (required, string) - `clientDataJSON` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
      * type (required, string) - Credential type. This should always be `"public-key"`

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "TSF9SUpSdj8rQmcpXTc9VX1VUzQtVC96fVdBZ0lKIXxdKycvVGNVMw",
  "refreshToken:" "eyJjb2RlIjoiWCxMN2Q2LWA6JzJcdTAwM2UhenFNb1FcImJaZlFLUyRwOGRPWj1bamBAZm9BXHUwMDNlIiwiZXhwaXJlc19hdCI6MTU5NDQwNTc1MX0",
}
```
* Response 400 (application/json)

```json
{
  "error": {
    "code": "webauthn",
    "message": "invalid signature"
  }
}
```

### <a name="request-device-challenge">Request device challenge [GET /api/v1/login/verify-device]</a>

A user holding a JWT token with status `identified` may request this endpoint to receive
a challenge value to sign. The signed value must be POSTed back to our service to
complete authentication.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```
{
  "publicKey": {
    "challenge": "b9aqYRIe/grw/Z4QfK1QvhYxrgsD3Cm743sFdrKdphI=",
    "rp": {
      "name": "Authenticator",
      "id": "authenticator.local"
    },
    "user": {
      "name": "ddddd@ddd.com",
      "displayName": "ddddd@ddd.com",
      "id": "MDFFQUREMjM4WFNaSkVUSDk4QUVEVkIyWVo="
    },
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      },
      {
        "type": "public-key",
        "alg": -35
      },
      {
        "type": "public-key",
        "alg": -36
      },
      {
        "type": "public-key",
        "alg": -257
      },
      {
        "type": "public-key",
        "alg": -258
      },
      {
        "type": "public-key",
        "alg": -259
      },
      {
        "type": "public-key",
        "alg": -37
      },
      {
        "type": "public-key",
        "alg": -38
      },
      {
        "type": "public-key",
        "alg": -39
      },
      {
        "type": "public-key",
        "alg": -8
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "timeout": 60000,
    "attestation": "direct"
  }
}
```

* Response 400 (application/json)

```
{
  "error": {
    "code": "webauthn",
    "message": "Error validating origin"
  }
}
```

## <a name="device-api">Device API</a>

Provides endpoints to manage WebAuthn capable devices for a User. Device registration is a
2 step process where the client retrieves necessary data to create a credential through a
POST request to `/api/v1/device`. On success, the payload is passed to the browser's
`navigator.credentials.create` API and the user is requested to sign the credential. This
credential contains a challenge which is verified during the second step of the API
through a POST request to `/api/v1/device/verify`.

### <a name="initiate-device">Initiate device registration [POST /api/v1/device]</a>

A user requests to register a new device using their `authorized` JWT token and receives
a WebAuthn challenge response.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```
{
  "publicKey": {
    "challenge": "b9aqYRIe/grw/Z4QfK1QvhYxrgsD3Cm743sFdrKdphI=",
    "rp": {
      "name": "Authenticator",
      "id": "authenticator.local"
    },
    "user": {
      "name": "ddddd@ddd.com",
      "displayName": "ddddd@ddd.com",
      "id": "MDFFQUREMjM4WFNaSkVUSDk4QUVEVkIyWVo="
    },
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      },
      {
        "type": "public-key",
        "alg": -35
      },
      {
        "type": "public-key",
        "alg": -36
      },
      {
        "type": "public-key",
        "alg": -257
      },
      {
        "type": "public-key",
        "alg": -258
      },
      {
        "type": "public-key",
        "alg": -259
      },
      {
        "type": "public-key",
        "alg": -37
      },
      {
        "type": "public-key",
        "alg": -38
      },
      {
        "type": "public-key",
        "alg": -39
      },
      {
        "type": "public-key",
        "alg": -8
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "timeout": 60000,
    "attestation": "direct"
  }
}
```

* Response 400 (application/json)

```
{
  "error": {
    "code": "webauthn",
    "message": "Error validating origin"
  }
}
```

### <a name="verify-device">Complete device registration [POST /api/v1/device/verify]</a>

A user completes device registration by signing a WebAuthn server challenge with their
device. On success, a refreshed JWT token is returned to the user.

* Request (application/json)

  * Parameters

      * id (required, string) - `id` generated from browser's navigator.credentials.create API
      * rawId (required, string) - `rawId` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
      * response (required, object)
          * attestationObject (required, string) - `attestationObject` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
          * clientDataJSON (required, string) - `clientDataJSON` generated from browser's navigator.credentials.create API and parsed from a `BufferSource` to a Base64 encoded string
      * type (required, string) - Credential type. This should always be `"public-key"`

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 201 (application/json)

```
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```
{
  "error": {
    "code": "webauthn",
    "message": "Error validating origin"
  }
}
```

### <a name="remove-device">Remove device [DELETE /api/v1/device/:device_id]</a>

A user removes a device from their account. Removed devices can no longer be used
for authentication. On success, a refreshed JWT token is returned to the user.


* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```
{
  "error": {
    "code": "bad_request,
    "message": "No device found"
  }
}
```

## <a name="token-api">Token API</a>

Provides endpoints to manage a User's token.

### <a name="token-revoke">Revoke a token [POST /api/v1/token/:token_id]</a>

A user revokes a token, rendering it invalid for authentication. Revoked
tokens can no longer be refreshed.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "status": "ok"
}
```
* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "invalid token ID"
  }
}
```

### <a name="token-verify">Verify a token [GET /api/v1/token/verify]</a>

A user confirms the currently used token is valid. This endpoint intends to be used
internally by other trusted services to verify a User is in possession of a JWT token
in an `authorized` state with accompanying client ID.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "status": "ok"
}
```

* Response 401 (application/json)

```json
{
  "error": {
    "code": "invalid_token",
    "message": "Token is invalid"
  }
}
```

### <a name="token-refresh">Refresh a token [GET /api/v1/token/refresh]</a>

A user refreshes an expiring token. Only `authorized` tokens may be refreshed.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "invalid_token",
    "message": "Token is revoked"
  }
}
```

## <a name="totp-api">TOTP API</a>

Provides endpoints to manage TOTP secret configuration on a user. By default, 2FA is enabled
on all users through delivery of an OTP code via a verified email or SMS. Users may instead
opt to generate a TOTP code through a supported app or device.

A client initiates a request to `api/v1/totp` to generate a new TFA secret on their profile.
If TOTP is already enabled for the user, this request will fail. After successfully creating
a secret, the server will return a a [TOTP URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) containing the TFA secret value. Clients may
use this string to generate a QR code to be scanned by the user, or optionally render
the URI contents for manual entry.

TOTP is enabled after the user generates a TOTP code sends it back to the server through
a POST request to `api/v1/totp/configure`.

If a user wishes to disable TOTP, they make a DELETE request to `api/v1/totp/configure`
with a valid TOTP code.

### <a name="totp-secret">Generate TOTP secret [POST /api/v1/totp]</a>

A user requests a new TOTP URI to generate TOTP codes.

* Request (application/json)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "totp": "otpauth://totp/Example:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "totp is already configured"
  }
}
```

### <a name="enable-totp">Enable TOTP [POST /api/v1/totp/configure]</a>

A user enables TOTP as a 2FA method after sending us a valid TOTP code generated by their
secret key.

* Request (application/json)

  * Parameters

      * code (required, string) - 6 digit code sent to user.

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 201 (application/json)

```json
{}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "totp is already configured"
  }
}
```

### <a name="disable-totp">Disable TOTP [DELETE /api/v1/totp/configure]</a>

A user disables TOTP as a 2FA method after sending us a valid TOTP code generated by their
secret key.

* Request (application/json)

  * Parameters

      * code (required, string) - 6 digit code sent to user.

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "totp is not enabled"
  }
}
```

## <a name="contact-api">Contact API</a>

Provides endpoints to allow users to manage their contact addresses for OTP
delivery. Users may add/remove an address, or optionally leave an address
attached to their profile while disabling it as an OTP delivery channel.

Addresses may not be disabled for OTP delivery unless an alternative 2fA method
such as TOTP or FIDO is enabled on the account.

### <a name="request-address-update">Request address update [POST /api/v1/contact/check-address]</a>

Request a new address (email or phone number) to be added onto the account.
On receipt, a randomly generate OTP code will be delivered to the new address
and the client will receive a refreshed JWT token containing the OTP hash. Clients
are expected to send the OTP back through `api/v1/contact/verify` in order
to complete the address change.

* Request (application/json)

  * Parameters

      * deliveryMethod (required, string) - `email` or `phone`
      * address (required, string) - Email address or phone number with country code

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 202 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "deliveryMethod must be `phone` or `email`"
  }
}
```

### <a name="disable-address">Disable address [POST /api/v1/contact/disable]</a>

Disable an address from receiving OTP codes. If a secondary 2FA method is enabled on
the profile (an alternative contact address, TOTP, or FIDO device), users may opt
to disable a contact address from being used as a 2FA method. On success, a refreshed
JWT token will be returned to the user.

* Request (application/json)

  * Parameters

      * deliveryMethod (required, string) - Delivery method to be disabled (`email` or `phone`)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 202 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "deliveryMethod must be `phone` or `email`"
  }
}
```

### <a name="verify-address">Verify address [POST /api/v1/contact/verify]</a>

Verify ownership of an address by submitting an OTP code. This is the follow up step
to `api/v1/contact/check-address`. Verified addresses are enabled as an OTP delivery
channel by default unless the client explicitly requests otherwise. On success, a
refreshed JWT token will be returned to the user.

* Request (application/json)

  * Parameters

      * code (required, string) - OTP code delivered to address
      * isDisabled (optional, boolean) - Boolean to disable the address from OTP delivery

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "deliveryMethod must be `phone` or `email`"
  }
}
```

### <a name="remove-address">Remove address [POST /api/v1/contact/remove]</a>

Remove an address from a user's profile. A removed address must go through the 2 step
process (request change -> verify ownership) to be re-added to the account in the future.
On success, a refreshed JWT token will be returned to the user.

* Request (application/json)

  * Parameters

      * deliveryMethod (required, string) - Delivery method to be disabled (`email` or `phone`)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 200 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "deliveryMethod must be `phone` or `email`"
  }
}
```

### <a name="resend-otp">Resend OTP to address [POST /api/v1/contact/send]</a>

Reesend an OTP to a verified address. If an OTP is not received during login, it may
be requested again through this endpoint. A refreshed `PreAuthorized` JWT token (retrieved
during the first step of login) is required for this endpoint.

User's who are already authenticated and are re-requesting an OTP should use
`api/v1/contact/check-address` instead.

* Request (application/json)

  * Parameters

      * deliveryMethod (required, string) - Delivery method to be disabled (`email` or `phone`)

  * Headers

      * Authorization: `Bearer <jwtToken>`
      * Cookie: `CLIENTID=<clientID>`

* Response 202 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA"
}
```

* Response 400 (application/json)

```json
{
  "error": {
    "code": "bad_request",
    "message": "deliveryMethod must be `phone` or `email`"
  }
}
```
