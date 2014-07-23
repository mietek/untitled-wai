--------------------------------------------------------------------------------

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module DB.Notify
    ( createNotify
    , listen
    )
  where

import qualified Database.PostgreSQL.Simple.Types as P

import DB (DB (..), extendID, sql)

--------------------------------------------------------------------------------

createNotify :: DB -> P.Identifier -> P.Identifier -> IO ()
createNotify db tab col = do
    createNotifyFunction db tab col
    createNotifyTrigger db tab

listen :: DB -> P.Identifier -> IO ()
listen db tab = do
    execute db [tab] [sql|
      LISTEN ?
    |]

--------------------------------------------------------------------------------

createNotifyFunction :: DB -> P.Identifier -> P.Identifier -> IO ()
createNotifyFunction db tab col = do
    let nfun = extendID tab "_notify"
    execute db (nfun, tab, col, tab, col, col, tab, col) [sql|
      CREATE FUNCTION ?() RETURNS trigger
      AS $plpgsql$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          PERFORM pg_notify('?', 'INSERT ' || NEW.?);
        ELSIF TG_OP = 'UPDATE' THEN
          PERFORM pg_notify('?', 'UPDATE ' || OLD.? || ' ' || NEW.?);
        ELSIF TG_OP = 'DELETE' THEN
          PERFORM pg_notify('?', 'DELETE ' || OLD.?);
        END IF;
        RETURN NULL;
      END;
      $plpgsql$ LANGUAGE plpgsql
    |]

createNotifyTrigger :: DB -> P.Identifier -> IO ()
createNotifyTrigger db tab = do
    let nfun = extendID tab "_notify"
    execute db (tab, nfun) [sql|
      CREATE TRIGGER notify
      AFTER INSERT OR UPDATE OR DELETE ON ?
      FOR EACH ROW EXECUTE PROCEDURE ?()
    |]

--------------------------------------------------------------------------------
