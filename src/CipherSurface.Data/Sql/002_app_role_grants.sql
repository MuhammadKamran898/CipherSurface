-- Privileges for the restricted application role.
-- Run as the schema OWNER. Replace cipher_app with the role your API and workers use.
-- Migrations run as the OWNER role; the application never connects as the owner.

GRANT USAGE ON SCHEMA public TO cipher_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cipher_app;

-- Append-only tables: insert and read only.
REVOKE UPDATE, DELETE, TRUNCATE ON
    audit_logs, policy_decisions, verification_checks, scan_run_authorization_checks
FROM cipher_app;

-- No hard deletes anywhere in the verification and authorization model.
REVOKE DELETE, TRUNCATE ON
    organizations, users, domains, authorization_grants, domain_disputes,
    verification_challenges, verification_attempts, verification_evidence,
    scope_rules, scan_runs
FROM cipher_app;

-- Migration history is owned by the migration role.
REVOKE ALL ON "__EFMigrationsHistory" FROM cipher_app;
