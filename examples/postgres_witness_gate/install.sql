-- Disposable PostgreSQL 16 research lab, NOT a production migration.
-- Install after examples/postgres_generic_gate/install.sql, using a trusted DB owner.
-- This wrapper is the ONLY executor function that should be granted to the
-- actor; revoke EXECUTE on generic.apply_text_change(uuid) from the actor.
--
-- An independent witness signs its own durable Ed25519 log, then provides a
-- separate 32-byte HMAC over the receipt hash, action UUID and issue timestamp.
-- PostgreSQL checks that HMAC with a *DB-owner-only* secret before executing
-- the already row/column/role-bound generic one-use transaction function.
-- The gateway can carry proof but cannot mint it.

BEGIN;

CREATE SCHEMA agentproof_crypto;
REVOKE ALL ON SCHEMA agentproof_crypto FROM PUBLIC;
CREATE EXTENSION pgcrypto WITH SCHEMA agentproof_crypto;

CREATE SCHEMA agentproof_witnessed;
REVOKE ALL ON SCHEMA agentproof_witnessed FROM PUBLIC;

CREATE TABLE agentproof_witnessed.config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    actor_role name NOT NULL,
    mac_key bytea NOT NULL CHECK (pg_catalog.octet_length(mac_key) = 32)
);
REVOKE ALL ON agentproof_witnessed.config FROM PUBLIC;

CREATE FUNCTION agentproof_witnessed.apply(
    request_id uuid,
    witness_receipt_sha256 text,
    witness_issued_at bigint,
    witness_mac_sha256 text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    operator_config agentproof_witnessed.config%ROWTYPE;
    now_epoch bigint;
    expected_mac text;
    mac_message text;
BEGIN
    SELECT * INTO operator_config
      FROM agentproof_witnessed.config WHERE singleton IS TRUE;
    IF NOT FOUND OR SESSION_USER <> operator_config.actor_role THEN
        RAISE EXCEPTION 'witness gate: caller not authorized'
            USING ERRCODE = '42501';
    END IF;

    IF witness_receipt_sha256 IS NULL
       OR witness_receipt_sha256 !~ '^[0-9a-f]{64}$'
       OR witness_mac_sha256 IS NULL
       OR witness_mac_sha256 !~ '^[0-9a-f]{64}$'
       OR witness_issued_at IS NULL THEN
        RAISE EXCEPTION 'witness gate: invalid admission'
            USING ERRCODE = '42501';
    END IF;

    now_epoch := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp())
    )::bigint;
    -- Fail closed on an unavailable/stale witness even when the operator's
    -- underlying database grant is still valid.
    IF witness_issued_at < now_epoch - 120
       OR witness_issued_at > now_epoch + 30 THEN
        RAISE EXCEPTION 'witness gate: admission expired or premature'
            USING ERRCODE = '42501';
    END IF;

    mac_message := 'AgentProof/witness-db/v1' || E'\n'
                   || request_id::text || E'\n'
                   || witness_receipt_sha256 || E'\n'
                   || witness_issued_at::text;
    expected_mac := pg_catalog.encode(
        agentproof_crypto.hmac(
            pg_catalog.convert_to(mac_message, 'UTF8'),
            operator_config.mac_key, 'sha256'
        ), 'hex'
    );
    IF expected_mac <> witness_mac_sha256 THEN
        RAISE EXCEPTION 'witness gate: invalid admission proof'
            USING ERRCODE = '42501';
    END IF;

    -- Both the admission verification and existing one-use grant validation
    -- execute within the caller's transaction. Underlying action grants remain
    -- locked, role-bound and consumed only after successful mutation.
    -- SESSION_USER remains the real actor despite SECURITY DEFINER nesting.
    RETURN agentproof_generic.apply_text_change(request_id);
END;
$body$;

REVOKE ALL ON ALL TABLES IN SCHEMA agentproof_witnessed FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agentproof_witnessed FROM PUBLIC;

COMMIT;

-- ONE-TIME ADMINISTRATOR SETUP, all inside a trusted transaction:
-- INSERT INTO agentproof_witnessed.config(actor_role, mac_key)
--     VALUES ('isolated_actor', decode('<32-byte-secret-as-64-hex>', 'hex'));
-- REVOKE EXECUTE ON FUNCTION agentproof_generic.apply_text_change(uuid)
--     FROM isolated_actor;
-- GRANT USAGE ON SCHEMA agentproof_witnessed TO isolated_actor;
-- GRANT EXECUTE ON FUNCTION
--     agentproof_witnessed.apply(uuid,text,bigint,text) TO isolated_actor;
--
-- Do not grant the actor access to config, agentproof_crypto, or the original
-- generic function; verify ACLs and role inheritance in deployment tests.
