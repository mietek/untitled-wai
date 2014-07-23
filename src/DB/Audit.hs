--------------------------------------------------------------------------------

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module DB.Audit
    ( createAudit
    )
  where

import qualified Database.PostgreSQL.Simple.Types as P

import DB (DB (..), sql)

--------------------------------------------------------------------------------

createAudit :: DB -> P.Identifier -> IO ()
createAudit db tab = do
    execute_ db [sql|
      CREATE EXTENSION hstore
    |]
    createAuditTable db tab
    createAuditFunction db tab
    createAuditTrigger db tab

--------------------------------------------------------------------------------

createAuditTable :: DB -> P.Identifier -> IO ()
createAuditTable db tab =
    execute db [tab] [sql|
      CREATE TABLE ?_audit()
        ( audit_id    serial      PRIMARY KEY WITH fillfactor(100)
        , audit_at    timestamptz NOT NULL DEFAULT current_timestamp
        , audit_query text        NOT NULL DEFAULT current_query()
        , audit_op    text        NOT NULL CHECK (op IN ('I', 'U', 'D'))
        , audit_old   hstore
        , audit_new   hstore
        )
    |]

createAuditFunction :: DB -> P.Identifier -> IO ()
createAuditFunction db tab =
    execute db (tab, tab, tab, tab) [sql|
      CREATE FUNCTION ?_audit() RETURNS trigger
      AS $plpgsql$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          INSERT INTO ? (op, new)
            VALUES ('I', hstore(NEW.*));
        ELSIF TG_OP = 'UPDATE' THEN
          INSERT INTO ? (op, old, new)
            VALUES ('U', hstore(OLD.*), hstore(NEW.*));
        ELSIF TG_OP = 'DELETE' THEN
          INSERT INTO ? (op, old)
            VALUES ('D', hstore(OLD.*));
        END IF;
        RETURN NULL;
      END;
      $plpgsql$ LANGUAGE plpgsql
    |]

createAuditTrigger :: DB -> P.Identifier -> IO ()
createAuditTrigger db tab =
    execute db (tab, tab) [sql|
      CREATE TRIGGER audit
      AFTER INSERT OR UPDATE OR DELETE ON ?
      FOR EACH ROW EXECUTE PROCEDURE ?_audit()
    |]

--------------------------------------------------------------------------------
