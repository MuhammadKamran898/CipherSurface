-- Smoke test for the SQL-level rules. Runs inside one transaction and rolls back.
-- Run as the schema owner on a database that has the schema and 001 applied:
--   psql -v ON_ERROR_STOP=1 -f 003_integrity_smoke_test.sql
-- Each block must RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN' only if a rule is broken.

BEGIN;

INSERT INTO organizations (id, name, status, created_at) VALUES ('00000000-0000-0000-0000-000000000001', 'Org A', 'Active', now());
INSERT INTO organizations (id, name, status, created_at) VALUES ('00000000-0000-0000-0000-000000000002', 'Org B', 'Active', now());
INSERT INTO users (id, email, email_confirmed, phone_number_confirmed, two_factor_enabled, lockout_enabled, access_failed_count, password_hash, status, created_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', 'a@example.com', false, false, false, true, 0, 'x', 'Active', now());
INSERT INTO domains (id, organization_id, name, status, created_by_user_id, created_at)
    VALUES ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-000000000001', 'brightcart.com', 'Verified', '00000000-0000-0000-0000-0000000000a1', now());

-- 1. Competing claim: a second org cannot hold the same name as Verified.
DO $$ BEGIN
    BEGIN
        INSERT INTO domains (id, organization_id, name, status, created_by_user_id, created_at)
        VALUES ('00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-000000000002', 'brightcart.com', 'Verified', '00000000-0000-0000-0000-0000000000a1', now());
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: duplicate active holder';
    EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;

-- 2. ...but a Disputed claimant record is allowed.
INSERT INTO domains (id, organization_id, name, status, created_by_user_id, created_at)
VALUES ('00000000-0000-0000-0000-0000000000d3', '00000000-0000-0000-0000-000000000002', 'brightcart.com', 'Disputed', '00000000-0000-0000-0000-0000000000a1', now());

-- 3. Scope rule inside the domain is accepted, outside is rejected.
INSERT INTO scope_rules (id, domain_id, rule_type, pattern, created_by_user_id, created_at)
VALUES (gen_random_uuid(), '00000000-0000-0000-0000-0000000000d1', 'Include', '*.brightcart.com', '00000000-0000-0000-0000-0000000000a1', now());
DO $$ BEGIN
    BEGIN
        INSERT INTO scope_rules (id, domain_id, rule_type, pattern, created_by_user_id, created_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-0000000000d1', 'Include', 'evilbrightcart.com', '00000000-0000-0000-0000-0000000000a1', now());
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: scope outside domain';
    EXCEPTION WHEN check_violation THEN NULL; END;
END $$;

-- 4. Audit log: chain rule and append-only.
INSERT INTO audit_logs (id, organization_id, sequence, occurred_at, actor_type, action, entity_type, data, hash)
VALUES ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-000000000001', 1, now(), 'System', 'test', 'Domain', '{}', '\x00');
DO $$ BEGIN
    BEGIN
        UPDATE audit_logs SET action = 'tampered';
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: audit update';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
    BEGIN
        DELETE FROM audit_logs;
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: audit delete';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
END $$;

-- 5. No hard delete of a domain.
DO $$ BEGIN
    BEGIN
        DELETE FROM domains WHERE id = '00000000-0000-0000-0000-0000000000d3';
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: domain delete';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
END $$;

-- 6. A Deny decision cannot start a scan.
INSERT INTO policy_decisions (id, organization_id, domain_id, trigger, outcome, failed_check_code,
                              effective_scope_snapshot, evidence_ids, scope_rules_hash, decided_at, expires_at)
VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000000000d1',
        'Manual', 'Deny', 'PROOF_ABSENT', '{}', '{}', 'h', now(), now() + interval '15 minutes');
DO $$ BEGIN
    BEGIN
        INSERT INTO scan_runs (id, policy_decision_id, targets, status, created_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-0000000000e1', ARRAY['brightcart.com'], 'Queued', now());
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: scan from Deny decision';
    EXCEPTION WHEN check_violation THEN NULL; END;
END $$;

-- 7. Invitations: one pending per organization and email, never Owner, core fields fixed, resolved ones frozen, no delete.
INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at)
VALUES ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-000000000001', 'invitee@example.com', 'Analyst',
        repeat('a', 64), 'Pending', '00000000-0000-0000-0000-0000000000a1', now(), now() + interval '7 days');
DO $$ BEGIN
    BEGIN
        INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'invitee@example.com', 'Viewer',
                repeat('b', 64), 'Pending', '00000000-0000-0000-0000-0000000000a1', now(), now() + interval '7 days');
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: second pending invitation';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    BEGIN
        INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'boss@example.com', 'Owner',
                repeat('c', 64), 'Pending', '00000000-0000-0000-0000-0000000000a1', now(), now() + interval '7 days');
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: invitation for Owner';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'sneaky@example.com', 'owner',
                repeat('d', 64), 'Pending', '00000000-0000-0000-0000-0000000000a1', now(), now() + interval '7 days');
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: invitation for a lower-case owner';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'badhash@example.com', 'Viewer',
                repeat('Z', 64), 'Pending', '00000000-0000-0000-0000-0000000000a1', now(), now() + interval '7 days');
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: invitation with a malformed token hash';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE invitations SET email = 'someone-else@example.com' WHERE id = '00000000-0000-0000-0000-0000000000f1';
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: invitation email change';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
    BEGIN
        DELETE FROM invitations WHERE id = '00000000-0000-0000-0000-0000000000f1';
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: invitation delete';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
END $$;
UPDATE invitations SET status = 'Revoked', resolved_at = now(), resolved_by_user_id = '00000000-0000-0000-0000-0000000000a1'
WHERE id = '00000000-0000-0000-0000-0000000000f1';
DO $$ BEGIN
    BEGIN
        UPDATE invitations SET status = 'Pending', resolved_at = NULL, resolved_by_user_id = NULL
        WHERE id = '00000000-0000-0000-0000-0000000000f1';
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: reopening a resolved invitation';
    EXCEPTION WHEN restrict_violation THEN NULL; END;
END $$;

ROLLBACK;
SELECT 'all integrity checks behaved as expected' AS result;
