--------------------------------------------------------------------------------

{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module DB.Audit
    ( createAuditSchema
    , createAudit
    )
  where

import qualified Database.PostgreSQL.Simple.Types as P

import DB (DB (..), extendID, sql)

--------------------------------------------------------------------------------

createAuditSchema :: DB -> IO ()
createAuditSchema db =
    withTransaction db $
      query1_ db [sql|
        SELECT EXISTS (SELECT * FROM pg_extension WHERE extname = 'hstore')
      |] >>= \case
        Just ([True]) -> return ()
        _ -> do
          putStrLn "Creating audit schema"
          execute_ db [sql|
            CREATE EXTENSION hstore
          |]

createAudit :: DB -> P.Identifier -> IO ()
createAudit db tab = do
    createAuditTable db tab
    createAuditFunction db tab
    createAuditTrigger db tab

--------------------------------------------------------------------------------

createAuditTable :: DB -> P.Identifier -> IO ()
createAuditTable db tab = do
    let atab = extendID tab "_audit"
    execute db [atab] [sql|
      CREATE TABLE IF NOT EXISTS ?
        ( audit_id    serial      PRIMARY KEY
        , audit_at    timestamptz NOT NULL DEFAULT current_timestamp
        , audit_query text        NOT NULL DEFAULT current_query()
        , audit_op    text        NOT NULL CHECK (audit_op IN ('I', 'U', 'D'))
        , audit_old   hstore
        , audit_new   hstore
        )
    |]

createAuditFunction :: DB -> P.Identifier -> IO ()
createAuditFunction db tab = do
    let afun = extendID tab "_audit"
    execute db (afun, tab, tab, tab) [sql|
      CREATE FUNCTION ?() RETURNS trigger
      AS $plpgsql$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          INSERT INTO ? (audit_op, audit_new)
            VALUES ('I', hstore(NEW.*));
        ELSIF TG_OP = 'UPDATE' THEN
          INSERT INTO ? (audit_op, audit_old, audit_new)
            VALUES ('U', hstore(OLD.*), hstore(NEW.*));
        ELSIF TG_OP = 'DELETE' THEN
          INSERT INTO ? (audit_op, audit_old)
            VALUES ('D', hstore(OLD.*));
        END IF;
        RETURN NULL;
      END;
      $plpgsql$ LANGUAGE plpgsql
    |]

createAuditTrigger :: DB -> P.Identifier -> IO ()
createAuditTrigger db tab = do
    let atab = extendID tab "_audit"
    execute db (tab, atab) [sql|
      CREATE TRIGGER audit
      AFTER INSERT OR UPDATE OR DELETE ON ?
      FOR EACH ROW EXECUTE PROCEDURE ?()
    |]

--------------------------------------------------------------------------------
