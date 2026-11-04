# CipherSurface.Api

The ASP.NET Core host. It is a thin HTTP layer over the existing services: it validates the request, authenticates the
caller, builds the `Actor` on the server, calls a service, and maps the result (or the `ServiceException` code) to HTTP.
It contains no business rules and opens no database transactions of its own.

## Endpoints

| Route | Login | Purpose |
|---|---|---|
| `POST /api/v1/setup/owner` | setup token | Creates the very first account and organization. Works only while no account exists. |
| `POST /api/v1/auth/login` | no | Returns an access token (RS256, 15 min) and a refresh token. |
| `POST /api/v1/auth/refresh` | no | Rotates the refresh token. Reusing an old one ends the whole session. |
| `POST /api/v1/auth/logout` | no | Ends the session behind a refresh token. |
| `POST /api/v1/auth/change-password` | yes | Changes the password and ends every session. |
| `GET /api/v1/me` | yes | The user and every organization they belong to. |
| `GET /api/v1/organization` | yes | The organization of this request, with the user's real role. |
| `POST /api/v1/invitations` | Owner/Admin | Invites an email as Admin, Analyst or Viewer. Returns the one-time token (and a link) once. |
| `GET /api/v1/invitations` | Owner/Admin | The organization's invitations and their states. Never a token. |
| `DELETE /api/v1/invitations/{id}` | Owner/Admin | Revokes a pending invitation. |
| `POST /api/v1/invitations/preview` | token | What a link is for (organization, email, role, expiry). Changes nothing. |
| `POST /api/v1/invitations/accept` | token | A new person accepts and chooses a password, which creates their account. |
| `POST /api/v1/invitations/accept/existing` | yes + token | A signed-in account whose email matches the invitation joins. |

## Registration is invitation-only

There is no public sign-up. An account comes from exactly one of two places: the one-time setup of the first owner, or
an invitation.

- An Owner or Admin invites an email address. The Owner role can never be invited; it exists only through setup.
- The invitation carries a one-time token. Only its SHA-256 hash is stored, the raw token is returned once to the
  inviter, and it is never written to logs, audit entries or later responses.
- The token is sent in a request body, never in a URL. The link puts it after `#`, which browsers never send to a server.
- Opening the link only previews. Accepting is an explicit `POST`.
- A person without an account accepts by choosing a password. Their email is **not** marked verified: there is no email
  provider yet, so holding the link is all that proves anything. A person who already has an account must be signed in
  with the same email.
- One pending invitation per organization and email. Inviting again supersedes the earlier one, whose token stops working.
- Acceptance runs in one transaction under an advisory lock and re-checks the status, expiry, the organization and that the
  inviter is still an Owner or Admin.
- Invitations last 7 days by default and the previews and accepts are rate limited per client.

Until an email provider exists, the inviter delivers the link. When one is added, requiring a verified email before an
existing account may accept is the next hardening step.

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
| `CipherSurface:Invitations:LifetimeDays` | no | 1 to 30, default 7. |
| `CipherSurface:Invitations:MaxPendingPerOrganization` | no | Open invitations one organization may hold, 1 to 1000, default 100. |
| `CipherSurface:Invitations:AcceptBaseUrl` | no | Where the web app handles links, for example `https://app.example.com/accept-invitation` (`http` only for localhost). Unset means no link is made, only the token. |
| `CipherSurface:RateLimiting:AuthRequestsPerMinute` | no | Default 10 per client address, for the auth and setup endpoints. |
| `CipherSurface:RateLimiting:InvitationRequestsPerMinute` | no | Default 10 per client address, for invitation preview and accept. |
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
