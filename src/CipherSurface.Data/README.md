# CipherSurface.Data

EF Core model and PostgreSQL integrity rules for domain verification and scan authorization
(implementation step 1 of the baseline spec).

## Status

- EF Core owns the relational schema (tables, keys, indexes, check constraints) through migrations.
- The SQL scripts own what EF cannot express: `Sql/001` the triggers, `Sql/002` the privileges of the
  restricted application role, `Sql/003` a smoke test of the triggers.
- `MigrationTests` (in `CipherSurface.Services.Tests`) build a database from nothing with the migrations, apply
  001 and 002, run 003, and compare the result with the schema every other test uses.
- Targets `net10.0`.

## Set up

Create the migration once, from the repository root (needs `dotnet tool install --global dotnet-ef`). The
connection string is only read to choose the PostgreSQL provider; nothing connects while a migration is created.

```powershell
$env:CIPHERSURFACE_DB = "Host=localhost;Database=ciphersurface;Username=cipher_owner;Password=..."
dotnet ef migrations add InitialCreate --project src/CipherSurface.Data --startup-project src/CipherSurface.Data
```

Build a database, always as the owner role and always in this order:

```powershell
dotnet ef database update --project src/CipherSurface.Data --startup-project src/CipherSurface.Data
psql -v ON_ERROR_STOP=1 -f src/CipherSurface.Data/Sql/001_integrity.sql        # triggers; safe to re-run
psql -v ON_ERROR_STOP=1 -f src/CipherSurface.Data/Sql/002_app_role_grants.sql  # after creating the cipher_app role
psql -v ON_ERROR_STOP=1 -f src/CipherSurface.Data/Sql/003_integrity_smoke_test.sql   # optional: proves the rules hold
```

Run 001 and 002 again after every migration that adds or renames tables: 002 grants privileges on the tables
that exist when it runs.

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
