# CipherSurface.Api

The ASP.NET Core host. It is a thin HTTP layer over the existing services: it validates the request, authenticates the
caller, builds the `Actor` on the server, calls a service, and maps the result (or the `ServiceException` code) to HTTP.
It contains no business rules and opens no database transactions of its own.

## Batch 1 endpoints

| Route | Login | Purpose |
|---|---|---|
| `POST /api/v1/setup/owner` | setup token | Creates the very first account and organization. Works only while no account exists. |
| `POST /api/v1/auth/login` | no | Returns an access token (RS256, 15 min) and a refresh token. |
| `POST /api/v1/auth/refresh` | no | Rotates the refresh token. Reusing an old one ends the whole session. |
| `POST /api/v1/auth/logout` | no | Ends the session behind a refresh token. |
| `POST /api/v1/auth/change-password` | yes | Changes the password and ends every session. |
| `GET /api/v1/me` | yes | The user and every organization they belong to. |
| `GET /api/v1/organization` | yes | The organization of this request, with the user's real role. |

There is no public registration. More members arrive through invitations (a later step); until then the only account
creation path is the one-time setup above.

## Organization context

A user can belong to several organizations. Send `X-Organization-Id` to choose one. The header only **selects**: the
membership and the role are read from the database on every request, and an organization the user does not belong to is
refused. With exactly one membership the header may be left out; with several and no header the API answers
`OrganizationRequired` instead of guessing. No request body ever carries a user id, organization or role.

## Errors

Every error is `application/problem+json` (RFC 9457) with a stable `code`, for example:

```json
{ "type": "about:blank", "title": "Conflict", "status": 409, "detail": "This rule already exists for the domain.", "code": "RuleExists", "traceId": "..." }
```

`ErrorCatalog` maps each service error code to a status. A code without a status, or any unexpected exception, becomes
a generic 500 and is logged on the server only. A test fails if a service can throw a code the catalog does not know.

## Configuration

Set values in `appsettings` or as environment variables (`CipherSurface__Jwt__PrivateKeyFile`). The API refuses to start
on invalid configuration, and error messages never contain secrets.

| Setting | Required | Meaning |
|---|---|---|
| `ConnectionStrings:CipherSurface` | yes | PostgreSQL connection string (use the `cipher_app` role in production). |
| `CipherSurface:Jwt:PrivateKeyFile` | yes | Path to an RSA private key (PEM, 2048 bits or more) **outside the repository**. On Linux the file must be mode 600. |
| `CipherSurface:Jwt:KeyId` | yes | Key id written to the `kid` header of every token. |
| `CipherSurface:Jwt:RetiredPublicKeys:N:KeyId` / `:File` | no | Public keys of rotated-out keys, trusted only until their tokens expire. |
| `CipherSurface:Jwt:Issuer` / `:Audience` | no | Defaults `ciphersurface` / `ciphersurface-api`. |
| `CipherSurface:Setup:Token` | no | 32+ characters. Unset means setup is disabled. |
| `CipherSurface:PlatformAdmins:UserIds:N` | no | User ids that are platform administrators. Empty means nobody is. |
| `CipherSurface:Cors:AllowedOrigins:N` | no | Exact origins such as `https://app.example.com`. Empty means no cross-origin access. |
| `CipherSurface:ForwardedHeaders:KnownProxies:N` | no | Proxy IPs trusted to set `X-Forwarded-For`. Empty means the header is ignored. |
| `CipherSurface:RateLimiting:AuthRequestsPerMinute` | no | Default 10 per client address, for the auth and setup endpoints. |
| `CipherSurface:RateLimiting:GlobalRequestsPerMinute` | no | Default 300 per client address. |

### Creating a development signing key

```powershell
# outside the repository, for example in your user profile
New-Item -ItemType Directory -Force "$env:USERPROFILE\.ciphersurface" | Out-Null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$env:USERPROFILE\.ciphersurface\jwt-private.pem"
# keep it readable by your account only
icacls "$env:USERPROFILE\.ciphersurface\jwt-private.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"

$env:CipherSurface__Jwt__PrivateKeyFile = "$env:USERPROFILE\.ciphersurface\jwt-private.pem"
$env:CipherSurface__Jwt__KeyId = "dev-1"
```

Never commit a private key or put one in a Docker image. In production mount the key as a secret from a secrets
manager; nothing else changes. To rotate: create a new key with a new id, add the old **public** key under
`RetiredPublicKeys`, and remove it once the old tokens have expired (15 minutes).

### Platform administrators

List user ids under `CipherSurface:PlatformAdmins:UserIds`. The decision is made on the server from the id in the
validated token. Nothing in a request can claim it, and an empty list means nobody is an administrator.

### Behind a reverse proxy

Set `ForwardedHeaders:KnownProxies` to the proxy's address, otherwise every client appears to come from the proxy and
shares one rate limit. TLS is expected to end at the proxy.
