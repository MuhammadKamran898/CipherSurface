-- Smoke test for the SQL-level rules. Runs inside one transaction and rolls back.
-- Run as the schema owner on a database that has the schema and 001 applied:
--   psql -v ON_ERROR_STOP=1 -f 003_integrity_smoke_test.sql
-- Each block must RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN' only if a rule is broken.

BEGIN;

INSERT INTO organizations (id, name, status, created_at) VALUES ('00000000-0000-0000-0000-000000000001', 'Org A', 'Active', now());
INSERT INTO organizations (id, name, status, created_at) VALUES ('00000000-0000-0000-0000-000000000002', 'Org B', 'Active', now());
INSERT INTO users (id, email, password_hash, status, created_at) VALUES ('00000000-0000-0000-0000-0000000000a1', 'a@example.com', 'x', 'Active', now());
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
        INSERT INTO scan_runs (id, policy_decision_id, status, created_at)
        VALUES (gen_random_uuid(), '00000000-0000-0000-0000-0000000000e1', 'Queued', now());
        RAISE EXCEPTION 'EXPECTED FAILURE DID NOT HAPPEN: scan from Deny decision';
    EXCEPTION WHEN check_violation THEN NULL; END;
END $$;

ROLLBACK;
SELECT 'all integrity checks behaved as expected' AS result;
