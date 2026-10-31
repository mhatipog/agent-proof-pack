-- Sandbox-only transactional effect gate (PostgreSQL 16).
-- This is a reference pattern: tables public.customers and public.invoices are
-- created by the fixture; do not install this script on an existing production DB.
-- Admin owns this schema, triggers and grant data. Restricted actors receive
-- EXECUTE only on apply_customer_status(uuid), never direct table writes.
BEGIN;

CREATE SCHEMA agentproof_guard;
REVOKE ALL ON SCHEMA agentproof_guard FROM PUBLIC;

CREATE TABLE agentproof_guard.action_grants (
    action_id uuid PRIMARY KEY,
    customer_id text NOT NULL,
    executor_role name NOT NULL,
    from_status text NOT NULL,
    to_status text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT changed_status CHECK (from_status <> to_status)
);

CREATE TABLE agentproof_guard.active_actions (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    action_id uuid NOT NULL REFERENCES agentproof_guard.action_grants(action_id),
    PRIMARY KEY (backend_pid, transaction_id)
);

-- A receipt is visible to a separately privileged observer only after the
-- surrounding transaction commits. An exception rolls the receipt back too.
-- This is an in-database event record, not an externally signed audit log.
CREATE TABLE agentproof_guard.committed_actions (
    action_id uuid PRIMARY KEY REFERENCES agentproof_guard.action_grants(action_id),
    transaction_id bigint NOT NULL,
    executor_role name NOT NULL,
    customer_id text NOT NULL,
    from_status text NOT NULL,
    to_status text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

-- Actual row effect from the guarded trigger. Created and rolled back in
-- exactly the same PostgreSQL transaction as the protected customer update.
-- One row per approval: a second guarded mutation aborts the transaction.
CREATE TABLE agentproof_guard.row_effects (
    action_id uuid PRIMARY KEY REFERENCES agentproof_guard.action_grants(action_id),
    transaction_id bigint NOT NULL,
    customer_id text NOT NULL,
    from_status text NOT NULL,
    to_status text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

REVOKE ALL ON ALL TABLES IN SCHEMA agentproof_guard FROM PUBLIC;

-- Any write to an invoice is outside the approved customer-status action.
-- This includes writes originating from another table's AFTER trigger.
CREATE FUNCTION agentproof_guard.reject_unapproved_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $guard$
BEGIN
    RAISE EXCEPTION 'effect gate: unapproved write to %', TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$guard$;

-- A customer modification is permitted only while an owner-controlled grant
-- is active in this precise backend and transaction. Transaction-local GUCs
-- are intentionally NOT used; the caller could spoof SET LOCAL variables.
CREATE FUNCTION agentproof_guard.guard_customer()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $guard$
DECLARE
    grant_record agentproof_guard.action_grants%ROWTYPE;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'effect gate: customer insert/delete denied'
            USING ERRCODE = '42501';
    END IF;

    SELECT g.* INTO grant_record
      FROM agentproof_guard.active_actions AS ctx
      JOIN agentproof_guard.action_grants AS g ON g.action_id = ctx.action_id
     WHERE ctx.backend_pid = pg_catalog.pg_backend_pid()
       AND ctx.transaction_id = pg_catalog.txid_current();

    IF NOT FOUND OR grant_record.consumed_at IS NOT NULL
       OR grant_record.expires_at <= pg_catalog.clock_timestamp()
       OR OLD.id IS DISTINCT FROM grant_record.customer_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR OLD.status IS DISTINCT FROM grant_record.from_status
       OR NEW.status IS DISTINCT FROM grant_record.to_status
       OR (pg_catalog.to_jsonb(NEW) - 'status')
          IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'status') THEN
        RAISE EXCEPTION 'effect gate: customer change outside exact grant'
            USING ERRCODE = '42501';
    END IF;

    -- Do not rely on the executor's "applied" return value: this trigger
    -- writes evidence of the row transition it actually accepted. Its event
    -- and the separately written committed_actions receipt are atomic with
    -- the business mutation, and invisible to other sessions pre-commit.
    INSERT INTO agentproof_guard.row_effects
      (action_id, transaction_id, customer_id, from_status, to_status)
    VALUES (grant_record.action_id, pg_catalog.txid_current(),
            OLD.id, OLD.status, NEW.status);
    RETURN NEW;
END;
$guard$;

-- The only authorized entry point. It locks the grant, requires its exact
-- pre-state, marks one-use consumption, and cleans the active context before
-- returning. If any trigger fails, PostgreSQL rolls back ALL effects and
-- grant consumption in the same transaction.
CREATE FUNCTION agentproof_guard.apply_customer_status(request_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $apply$
DECLARE
    grant_record agentproof_guard.action_grants%ROWTYPE;
    changed integer;
BEGIN
    SELECT * INTO grant_record
      FROM agentproof_guard.action_grants
     WHERE action_id = request_id FOR UPDATE;
    IF NOT FOUND OR grant_record.consumed_at IS NOT NULL
       OR grant_record.expires_at <= pg_catalog.clock_timestamp()
       OR grant_record.executor_role <> SESSION_USER THEN
        RAISE EXCEPTION 'effect gate: grant missing, expired or already used'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO agentproof_guard.active_actions(backend_pid, transaction_id, action_id)
    VALUES (pg_catalog.pg_backend_pid(), pg_catalog.txid_current(), request_id);

    UPDATE public.customers
       SET status = grant_record.to_status
     WHERE id = grant_record.customer_id
       AND status = grant_record.from_status;

    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'effect gate: expected exactly one matching pre-state row'
            USING ERRCODE = '42501';
    END IF;

    DELETE FROM agentproof_guard.active_actions
     WHERE backend_pid = pg_catalog.pg_backend_pid()
       AND transaction_id = pg_catalog.txid_current()
       AND action_id = request_id;

    UPDATE agentproof_guard.action_grants
       SET consumed_at = pg_catalog.clock_timestamp()
     WHERE action_id = request_id;

    -- Only visible after the same transaction commits successfully.
    INSERT INTO agentproof_guard.committed_actions
      (action_id, transaction_id, executor_role, customer_id, from_status, to_status)
    VALUES (request_id, pg_catalog.txid_current(), SESSION_USER,
            grant_record.customer_id, grant_record.from_status, grant_record.to_status);

    RETURN 'applied';
END;
$apply$;

CREATE TRIGGER agentproof_customer_write
BEFORE INSERT OR UPDATE OR DELETE ON public.customers
FOR EACH ROW EXECUTE FUNCTION agentproof_guard.guard_customer();

CREATE TRIGGER agentproof_invoice_write
BEFORE INSERT OR UPDATE OR DELETE ON public.invoices
FOR EACH ROW EXECUTE FUNCTION agentproof_guard.reject_unapproved_write();

CREATE TRIGGER agentproof_customer_truncate
BEFORE TRUNCATE ON public.customers
FOR EACH STATEMENT EXECUTE FUNCTION agentproof_guard.reject_unapproved_write();

CREATE TRIGGER agentproof_invoice_truncate
BEFORE TRUNCATE ON public.invoices
FOR EACH STATEMENT EXECUTE FUNCTION agentproof_guard.reject_unapproved_write();

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agentproof_guard FROM PUBLIC;
COMMIT;
