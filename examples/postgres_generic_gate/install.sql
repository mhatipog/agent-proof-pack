-- EXPERIMENTAL, DISPOSABLE POSTGRESQL 16 ONLY.
-- Generic guarded update of one TEXT/VARCHAR column in one protected table.
-- The trusted schema owner installs this; the agent never has DDL rights.
-- Reject all other DML on every table explicitly enrolled with protect_table().
-- Not a production migration or a general-purpose database firewall.
BEGIN;

CREATE SCHEMA agentproof_generic;
REVOKE ALL ON SCHEMA agentproof_generic FROM PUBLIC;

CREATE TABLE agentproof_generic.grants (
    action_id uuid PRIMARY KEY,
    target_oid oid NOT NULL,
    key_column name NOT NULL,
    key_value text NOT NULL,
    update_column name NOT NULL,
    old_value text NOT NULL,
    new_value text NOT NULL,
    executor_role name NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    consumed_at timestamptz,
    CONSTRAINT value_changed CHECK (old_value <> new_value),
    CONSTRAINT different_columns CHECK (key_column <> update_column)
);

CREATE TABLE agentproof_generic.active (
    backend_pid integer NOT NULL,
    txid bigint NOT NULL,
    action_id uuid NOT NULL REFERENCES agentproof_generic.grants(action_id),
    PRIMARY KEY (backend_pid, txid)
);

CREATE TABLE agentproof_generic.committed (
    action_id uuid PRIMARY KEY REFERENCES agentproof_generic.grants(action_id),
    txid bigint NOT NULL,
    executor_role name NOT NULL,
    target_oid oid NOT NULL,
    key_column name NOT NULL,
    key_value text NOT NULL,
    update_column name NOT NULL,
    old_value text NOT NULL,
    new_value text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

REVOKE ALL ON ALL TABLES IN SCHEMA agentproof_generic FROM PUBLIC;

CREATE FUNCTION agentproof_generic.guard_row()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    approval agentproof_generic.grants%ROWTYPE;
    old_record jsonb;
    new_record jsonb;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'effect gate: insertion/deletion refused on protected table'
            USING ERRCODE = '42501';
    END IF;
    SELECT g.* INTO approval
      FROM agentproof_generic.active a
      JOIN agentproof_generic.grants g ON g.action_id = a.action_id
     WHERE a.backend_pid = pg_catalog.pg_backend_pid()
       AND a.txid = pg_catalog.txid_current();
    IF NOT FOUND
       OR approval.target_oid <> TG_RELID
       OR approval.executor_role <> SESSION_USER
       OR approval.consumed_at IS NOT NULL
       OR approval.revoked_at IS NOT NULL
       OR approval.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'effect gate: no matching transaction-bound grant'
            USING ERRCODE = '42501';
    END IF;
    old_record := pg_catalog.to_jsonb(OLD);
    new_record := pg_catalog.to_jsonb(NEW);
    IF old_record ->> approval.key_column <> approval.key_value
       OR new_record ->> approval.key_column <> approval.key_value
       OR old_record ->> approval.update_column <> approval.old_value
       OR new_record ->> approval.update_column <> approval.new_value
       OR (old_record - approval.update_column)
            IS DISTINCT FROM (new_record - approval.update_column) THEN
        RAISE EXCEPTION 'effect gate: record changed beyond exact approved effect'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$body$;

CREATE FUNCTION agentproof_generic.reject_truncate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
BEGIN
    RAISE EXCEPTION 'effect gate: truncation of protected table denied'
        USING ERRCODE = '42501';
END;
$body$;

-- Only an owner/controller installs guards. Execute permissions are revoked
-- before transaction commit, so other sessions never observe a public window.
CREATE FUNCTION agentproof_generic.protect_table(rel regclass)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    schema_name text;
    relation_name text;
BEGIN
    SELECT n.nspname, c.relname INTO schema_name, relation_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE c.oid = rel AND c.relkind = 'r'
       AND n.nspname NOT LIKE 'pg_%'
       AND n.nspname <> 'information_schema';
    IF schema_name IS NULL THEN
        RAISE EXCEPTION 'effect gate: only ordinary non-system tables supported'
            USING ERRCODE = '42501';
    END IF;
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER agentproof_exact_row BEFORE INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION agentproof_generic.guard_row()',
      schema_name, relation_name);
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER agentproof_no_truncate BEFORE TRUNCATE ON %I.%I FOR EACH STATEMENT EXECUTE FUNCTION agentproof_generic.reject_truncate()',
      schema_name, relation_name);
END;
$body$;

CREATE FUNCTION agentproof_generic.apply_text_change(request_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    approval agentproof_generic.grants%ROWTYPE;
    schema_name text;
    relation_name text;
    changed integer;
    is_pk boolean;
    is_text boolean;
BEGIN
    SELECT * INTO approval FROM agentproof_generic.grants
     WHERE action_id = request_id FOR UPDATE;
    IF NOT FOUND
       OR approval.consumed_at IS NOT NULL
       OR approval.revoked_at IS NOT NULL
       OR approval.expires_at <= pg_catalog.clock_timestamp()
       OR approval.executor_role <> SESSION_USER THEN
        RAISE EXCEPTION 'effect gate: grant missing, expired or wrong role'
            USING ERRCODE = '42501';
    END IF;
    SELECT n.nspname, c.relname INTO schema_name, relation_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE c.oid = approval.target_oid AND c.relkind = 'r'
       AND n.nspname NOT LIKE 'pg_%'
       AND n.nspname <> 'information_schema';
    IF schema_name IS NULL THEN
        RAISE EXCEPTION 'effect gate: unsupported target relation'
            USING ERRCODE = '42501';
    END IF;

    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_index idx
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = idx.indrelid AND a.attnum = idx.indkey[0]
      WHERE idx.indrelid = approval.target_oid AND idx.indisprimary
        AND idx.indnkeyatts = 1 AND a.attname = approval.key_column
    ) INTO is_pk;
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute a
       WHERE a.attrelid = approval.target_oid
         AND a.attname = approval.update_column
         AND a.attnum > 0 AND NOT a.attisdropped
         AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype)
    ) INTO is_text;
    IF NOT is_pk OR NOT is_text THEN
        RAISE EXCEPTION 'effect gate: target must have exact single-column PK and text update field'
            USING ERRCODE = '42501';
    END IF;
    -- The exact relation must already be guarded; otherwise the table could
    -- have unreviewed downstream triggers. Extra tables are separately enrolled.
    IF NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger t
       WHERE t.tgrelid = approval.target_oid
         AND t.tgname = 'agentproof_exact_row' AND t.tgenabled = 'O'
    ) THEN
        RAISE EXCEPTION 'effect gate: table missing active guard trigger'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO agentproof_generic.active(backend_pid, txid, action_id)
    VALUES (pg_catalog.pg_backend_pid(), pg_catalog.txid_current(), request_id);

    EXECUTE pg_catalog.format(
        'UPDATE %I.%I SET %I = $1 WHERE %I::text = $2 AND %I::text = $3',
        schema_name, relation_name, approval.update_column, approval.key_column,
        approval.update_column)
        USING approval.new_value, approval.key_value, approval.old_value;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'effect gate: stale or missing target row'
            USING ERRCODE = '42501';
    END IF;

    DELETE FROM agentproof_generic.active
     WHERE backend_pid = pg_catalog.pg_backend_pid()
       AND txid = pg_catalog.txid_current() AND action_id = request_id;
    UPDATE agentproof_generic.grants
       SET consumed_at = pg_catalog.clock_timestamp()
     WHERE action_id = request_id;
    INSERT INTO agentproof_generic.committed
      (action_id, txid, executor_role, target_oid, key_column, key_value,
       update_column, old_value, new_value)
    VALUES (request_id, pg_catalog.txid_current(), SESSION_USER,
            approval.target_oid, approval.key_column, approval.key_value,
            approval.update_column, approval.old_value, approval.new_value);
    RETURN 'applied';
END;
$body$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agentproof_generic FROM PUBLIC;
COMMIT;
