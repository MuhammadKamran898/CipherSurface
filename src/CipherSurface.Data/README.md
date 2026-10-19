# CipherSurface.Data

EF Core model and PostgreSQL integrity rules for domain verification and scan authorization
(implementation step 1 of the baseline spec).

## Status

- SQL scripts (`Sql/001`, `Sql/003`): executed against PostgreSQL 16 and passing.
- C# code: written against the spec but **not compiled yet** (no .NET SDK or NuGet access where it was written).
  Run `dotnet build` first and fix anything the compiler reports.
- Targets `net10.0`. On .NET 8 or 9, change `TargetFramework` and the `10.0.*` package versions to match.

## Set up

```bash
dotnet add package ... # already in the csproj; just: dotnet restore
export CIPHERSURFACE_DB="Host=localhost;Database=ciphersurface;Username=cipher_owner;Password=..."
dotnet ef migrations add Initial
dotnet ef database update
psql -f Sql/001_integrity.sql        # as the owner role
psql -f Sql/002_app_role_grants.sql  # after creating the cipher_app role
psql -f Sql/003_integrity_smoke_test.sql   # optional: proves the rules hold
```

Migrations run as the owner role. The API and workers connect as `cipher_app`, which cannot update,
delete or truncate append-only tables.

## Where each invariant is enforced

| Invariant | Enforced by |
|---|---|
| One active holder per domain name | Partial unique index `ux_domains_active_holder` |
| One active challenge per domain and method | Partial unique index `ux_challenges_one_active_per_method` |
| One evidence row per challenge | Unique FK on `verification_evidence.challenge_id` |
| Wildcard scope only from DNS; email is root-only and expires | Check constraints on `verification_evidence` |
| A check has exactly one parent (attempt or evidence) | `ck_checks_exactly_one_parent` |
| Retried jobs are harmless, new cycles are not rejected | `ux_checks_attempt_retry`, `ux_checks_run_retry` |
| One open dispute per claimant; incumbent differs from claimant | Partial unique index + check constraint |
| One active grant per domain | Partial unique index |
| Deny decisions carry a failed-check code | `ck_decisions_deny_has_code` |
| One decision authorizes exactly one scan | Required unique FK `scan_runs.policy_decision_id` |
| A scan needs an unexpired Allow decision | Trigger `cs_scan_requires_allow` |
| One scan per schedule occurrence | Partial unique index |
| Scope rule falls under its domain | Trigger `cs_scope_rule_within_domain` |
| Audit log, decisions, checks are append-only | Triggers + revoked privileges |
| No hard deletes of core records | `DeleteBehavior.Restrict` + triggers + revoked privileges |
| Audit chain starts at sequence 1 with no previous hash | `ck_audit_prev_hash_chain`, unique (org, sequence) |
| Two jobs cannot advance the same row | `xmin` concurrency token (`uint Version`) |

## Not in the database (service layer, next steps)

- Domain status derivation, the Scan Policy Gate, scope calculation.
- Audit hash computation and chain verification.
- Advisory lock for claim completion (`pg_advisory_xact_lock` on the normalized domain name).
- The rule that Lapsed/Expired evidence is never reactivated.

## Design notes

- Enums are stored as strings so filters like `status IN ('Verified', 'AtRisk')` read naturally.
- `audit_logs.sequence` was added to the spec's field list: the per-organization chain needs a stable order.
- Public-proof tokens are stored retrievable; the admin-email token must be stored hashed (`TokenIsHashed`).
