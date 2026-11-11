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
| `GET /api/v1/attestation` | yes | The authorization statement (version and text) a user must accept to add a domain. |
| `POST /api/v1/domains` | Owner/Admin | Adds a domain after the statement is accepted. The server stores the hash of its own text. |
| `GET /api/v1/domains` | any member | The organization's domains, paged (`page`, `pageSize` up to 200, optional `status`). |
| `GET /api/v1/domains/{id}` | any member | Status, authorization, evidence, open challenges, disputes. Another organization's id is `NotFound`. |
| `POST /api/v1/domains/{id}/challenges` | Owner/Admin | Issues a DNS TXT, HTTP file or HTML meta challenge and returns the instruction. |
| `POST /api/v1/domains/{id}/email-challenges` | Owner/Admin | Sends a confirmation email to a standard role mailbox on the domain. 503 until email is configured. |
| `POST /api/v1/challenges/{id}/verify` | Owner/Admin | One click, one attempt: checks DNS, the file or the meta tag. |
| `GET /api/v1/email-challenges/{id}` | Owner/Admin | What the email link is for. Changes nothing, so a mail scanner cannot use it up. |
| `POST /api/v1/email-challenges/{id}/confirm` | Owner/Admin | Confirms with the one-time token (in the body). Only this call consumes the link. |

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

## Domains and verification

- Reading (list, details) is open to every member. Every write needs an Owner or Admin of an **active** organization, and
  that is the first check, before the content of the request is looked at and before anything about the deployment
  (such as whether email is configured) is revealed: login, then organization, then role, then the rest.
- Every query is filtered by the caller's organization. A domain or challenge of another organization answers `NotFound`,
  exactly like one that does not exist. The same name may be added by two organizations; who owns it is decided by proof.
- The server owns the authorization text. The client sends the version it was shown and `accepted: true`; a stale version
  is `AttestationOutdated` (409). The stored hash is always of the text the user could read.
- DNS, file and meta tokens are public proofs, so an Owner or Admin can see the instruction of an open challenge again.
  Other roles see that a challenge exists, not its instruction. An email token is a secret: it is stored only as a hash,
  is mailed once, and is never returned by any endpoint.
- A dispute is shown to each side as "a dispute exists" with its own role. The other organization is never named.
- The Verify click can take several seconds because DNS is re-checked for propagation. Attempts are limited per user and
  per address by the service, and these endpoints have their own per-client limit (`RateLimiting:VerificationRequestsPerMinute`, default 30).
- Email links carry only the challenge id and the token after `#`, not the organization. A person with several
  organizations must send the `X-Organization-Id` of the organization that owns the domain, so the confirmation page has
  to find it (see below).

### Email confirmation page: finding the right organization

`GET /email-challenges/{id}` and `POST /email-challenges/{id}/confirm` check the role of the caller in the chosen
organization first, then look the challenge up inside that organization only:

| Caller in the chosen organization | Challenge belongs to that organization | Answer |
|---|---|---|
| Owner or Admin | yes | 200 |
| Owner or Admin | no, or it does not exist | 404 `NotFound` |
| Analyst or Viewer | any | 403 `NotAllowed` (the challenge is never looked up, so this reveals nothing about it) |
| Owner or Admin of a **suspended** organization | any | 403 `OrganizationSuspended` (writes and the preview are refused; the challenge is not looked up) |

The page therefore tries **every** membership of the signed-in user (from `GET /me`) and must not stop at the first 403:

1. 200: this is the organization; keep it and continue with that `X-Organization-Id`.
2. 404: try the next organization.
3. 403: remember its code (`NotAllowed` or `OrganizationSuspended`) and try the next organization.
4. No 200, but at least one 403: show a message for the code you saw ("you do not have permission to confirm this" for
   `NotAllowed`, "this organization is suspended" for `OrganizationSuspended`).
5. Every answer was 404: show that none of your organizations matches this link.

The page always sends `X-Organization-Id`; without it, a person with several organizations gets 400 `OrganizationRequired`.
Only the preview should be used for the search. Call `confirm` once, for the organization the preview selected, because
a confirm with a wrong token counts as a failed attempt.

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
| `CipherSurface:Verification:DnsServers:N` | no | Resolvers used for DNS TXT proof (1 to 5). Default: `1.1.1.1` and `8.8.8.8`. A resolver that is down never invalidates a proof another one confirms. |
| `CipherSurface:Verification:DnsTimeoutSeconds` | no | 1 to 30, default 5. |
| `CipherSurface:Verification:EmailConfirmationPage` | no | The web app page confirmation links open, `https` only, for example `https://app.example.com/verify-email`. The id and token are added after `#`. |
| `CipherSurface:Verification:PublicSuffixListFile` | no | Use this Public Suffix List file instead of the bundled one. |
| `CipherSurface:RateLimiting:AuthRequestsPerMinute` | no | Default 10 per client address, for the auth and setup endpoints. |
| `CipherSurface:RateLimiting:InvitationRequestsPerMinute` | no | Default 10 per client address, for invitation preview and accept. |
| `CipherSurface:RateLimiting:GlobalRequestsPerMinute` | no | Default 300 per client address. |

### The Public Suffix List

Domain onboarding refuses shared suffixes (`com`, `co.uk`, `github.io`) using the official Public Suffix List, and there
is deliberately no fallback list. It is committed under `src/CipherSurface.Services/Data/`. To refresh it, from the repository root:

```powershell
Invoke-WebRequest https://publicsuffix.org/list/public_suffix_list.dat -OutFile src/CipherSurface.Services/Data/public_suffix_list.dat
```

The file is committed and embedded in `CipherSurface.Services.dll`; if it is ever missing the build fails with `CSPSL001` and the command above, and an assembly built any other way refuses to start. The start-up log says which list was loaded. See `src/CipherSurface.Services/Data/README.md` for refreshing and for verifying a published build.

### Email verification needs a provider

Until an email provider is registered the admin-email method fails closed: issuing a confirmation is refused with
`EmailNotConfigured` (503) before anything is created, and nothing is logged in its place. No provider is built in.

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
