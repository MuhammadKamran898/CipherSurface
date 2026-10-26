-- CipherSurface integrity rules that EF Core cannot express.
-- Run as the schema OWNER, after the EF migration has created the tables.
-- Safe to re-run (idempotent).

-- ---------------------------------------------------------------------------
-- 1. Append-only tables: no UPDATE, DELETE or TRUNCATE, even for the table owner.
--    (The restricted app role also has these privileges revoked in 002.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cs_forbid_modification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % is not allowed: table is append-only', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END $$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['audit_logs', 'policy_decisions', 'verification_checks', 'scan_run_authorization_checks']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_append_only ON %I', t, t);
        EXECUTE format('CREATE TRIGGER trg_%s_append_only BEFORE UPDATE OR DELETE ON %I
                        FOR EACH ROW EXECUTE FUNCTION cs_forbid_modification()', t, t);
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_no_truncate ON %I', t, t);
        EXECUTE format('CREATE TRIGGER trg_%s_no_truncate BEFORE TRUNCATE ON %I
                        FOR EACH STATEMENT EXECUTE FUNCTION cs_forbid_modification()', t, t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 2. No hard deletes. History is kept; removal means a status change or soft delete.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cs_forbid_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'DELETE on % is not allowed: use a status change or soft delete', TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END $$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['organizations', 'users', 'domains', 'authorization_grants', 'domain_disputes',
                             'verification_challenges', 'verification_attempts', 'verification_evidence',
                             'scope_rules', 'scan_runs']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_no_delete ON %I', t, t);
        EXECUTE format('CREATE TRIGGER trg_%s_no_delete BEFORE DELETE ON %I
                        FOR EACH ROW EXECUTE FUNCTION cs_forbid_delete()', t, t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 3. A scope rule must fall under its domain: the domain itself, or any host below it.
--    "*.brightcart.com" and "shop.brightcart.com" pass; "evilbrightcart.com" does not.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cs_scope_rule_within_domain() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE d text;
BEGIN
    SELECT name INTO d FROM domains WHERE id = NEW.domain_id;
    IF NEW.pattern <> d AND right(NEW.pattern, length(d) + 1) <> ('.' || d) THEN
        RAISE EXCEPTION 'scope pattern % is outside domain %', NEW.pattern, d
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_scope_rules_within_domain ON scope_rules;
CREATE TRIGGER trg_scope_rules_within_domain
    BEFORE INSERT OR UPDATE OF pattern, domain_id ON scope_rules
    FOR EACH ROW EXECUTE FUNCTION cs_scope_rule_within_domain();

-- ---------------------------------------------------------------------------
-- 4. A scan may only be created from an Allow decision, and not after that decision expired
--    (judged by the scan row's own created_at, so application and database clocks cannot disagree).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cs_scan_requires_allow() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE o text; e timestamptz;
BEGIN
    SELECT outcome, expires_at INTO o, e FROM policy_decisions WHERE id = NEW.policy_decision_id;
    IF o IS DISTINCT FROM 'Allow' THEN
        RAISE EXCEPTION 'scan requires an Allow decision (decision % is %)', NEW.policy_decision_id, o
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.created_at > e THEN
        RAISE EXCEPTION 'scan created after policy decision % expired', NEW.policy_decision_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_scan_runs_requires_allow ON scan_runs;
CREATE TRIGGER trg_scan_runs_requires_allow
    BEFORE INSERT ON scan_runs
    FOR EACH ROW EXECUTE FUNCTION cs_scan_requires_allow();
