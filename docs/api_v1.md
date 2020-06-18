# Authenticator API


## Contents

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

  * [Revoke token](#revoke-token)
  * [Verify token](#verify-token)

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

      * email (optional, string) - Email address of the user.
      * phone (optional, string) - Phone number of the user.

* Response 201 (application/json)

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE4MTg2MDUsImp0aSI6IjAxRUFGVkMxMFBSRzE5REQyNUZFWUFRQVpLIiwiaXNzIjoiYXV0aGVudGljYXRvciIsImNsaWVudF9pZCI6IjA3ZmE3ODBiNjdmNTI3N2YzZTE0MDRjNDMyN2Y0NTBkYjllMzBlNGZjYTE4MmMwNmFkNzEyZDA5NTYwMWI0MTI1NWVlNjg2Y2JlNWI5NDBlZGZmMGVhYzcwZTVkZmY0NDU0MmVlZTI2ODE2NDBmNjA4YTljNmRmYWM2ZDg4NWNmIiwidXNlcl9pZCI6IjAxRUFGVkMwWUowUzZLM0Y5VjdKNDNGR1FCIiwiZW1haWwiOiJ0ZXN0OEB0ZXN0LmNvbSIsInBob25lX251bWJlciI6IiIsInN0YXRlIjoicHJlX2F1dGhvcml6ZWQiLCJjb2RlIjoiYjUwMDZhODU3MTIyNWIyMWNkZjVmYzgwZGNkNGU5ZGFmYzZlNGY3ODZhZTk1OTRjMmMzZGQ3NGY4NzRlYWM3OGNjYTVmYmRjYjk4ZjZjMDUxNDI2MmVlYjQzZDQ0ZWFmODhiNzUyODBkZWMyMjhhZjJhNWJmOTA5YWM4NGI4MjEifQ.N8l-mqp6hnWN2Z630hpGNITvfDR6PT4Yl2Rt52_HzWjG4NqWG8CfXJ8AntNDOfsvIGLR6t7qlVmUlUwd4cEwuA",
  "clientID": "aIXvJGIm72dqiwgUWNm3R4UyQIbByLDCzQCzOZWz"
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
as a new authorized user.

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
  "clientID": "aIXvJGIm72dqiwgUWNm3R4UyQIbByLDCzQCzOZWz"
}
```

## <a name="login-api">Login API</a>

Provides endpoints to manage user authentication. It is a 2-step API where a client
initiates login with a POST request to `api/v1/login`. After the initial request, they
will complete the multi-factor authentication requirement with a POST request to either
`api/v1/login/device` or `api/v1/login/code` to verify a device, randomly generated
code or TOTP code.

### Initiate login [POST /api/v1/login]

A user provides either an email or phone number and password for us to identify them.
On success we will return a JWT token with status `identified`.

### Complete login with code [POST /api/v1/login/verify-code]

A user submits a random server generated code or TOTP code. On success we will return
a JWT token with status `authorized`.

### Complete login with device [POST /api/v1/login/verify-device]

A user signs a server challenge with their WebAuthn capable device. On success we will
return a JWT token with status `authorized`.

### Request device challenge [GET /api/v1/login/verify-device]

A user holding a JWT token with status `identified` may request this endpoint to receive
a challenge value to sign. The signed value must be POSTed back to our service to
complete authentication.

* Response 200 (application/json)

```
{
  "publicKey": {
    "challenge": "",
    "rp": "",
    "user": "",
    "pubKeyCredParams": "",
    "authenticatorSelection": "",
    "timeout": "",
    "excludeCredentials": "",
    "attestation": "",
  },
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
device.

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
{}
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
for authentication.

## <a name="token-api">Token API</a>

Provides endpoints to manage a User's token.

### Revoke a token [POST /api/v1/token/:token_id]

A user revokes a token, rendering it invalid for authentication.

### Verify a token [GET /api/v1/token/verify]

A user confirms the currently used token is valid. This endpoint intends to be used
internally by other trusted services to verify a User's authentication.

## <a name="user-api">User API</a>

Provides endpoints to manage a User's account.

### Update MFA settings [PATCH /api/v1/user/:user_id]

Toggle settings to enforce MFA through SMS/email delivery of randomly generated codes,
TOTP generator, or WebAuthn device.

### Update password [PATCH /api/v1/user/:user_id]

Change's a user's password.
