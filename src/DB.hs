--------------------------------------------------------------------------------

{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE Rank2Types #-}

module DB
    ( DB (..)
    , initDB
    , sql
    )
  where

import Control.Monad (void)
import Data.String (fromString)
import Database.PostgreSQL.Simple.SqlQQ (sql)

import qualified Database.PostgreSQL.Simple as P

--------------------------------------------------------------------------------

data DB = DB
    { execute         :: (P.ToRow q) => q -> P.Query -> IO ()
    , execute_        :: P.Query -> IO ()
    , query           :: (P.ToRow q, P.FromRow r) => q -> P.Query -> IO [r]
    , query_          :: (P.FromRow r) => P.Query -> IO [r]
    , query1          :: (P.ToRow q, P.FromRow r) => q -> P.Query -> IO (Maybe r)
    , query1_         :: (P.FromRow r) => P.Query -> IO (Maybe r)
    , withTransaction :: forall a . IO a -> IO a
    }

data DBState = DBState
    { db' :: P.Connection
    }

--------------------------------------------------------------------------------

initDB :: String -> IO DB
initDB dburl = do
    db <- P.connectPostgreSQL (fromString dburl)
    let
      st = DBState
        { db' = db
        }
    return $ DB
        { execute         = execute' st
        , execute_        = execute_' st
        , query           = query' st
        , query_          = query_' st
        , query1          = query1' st
        , query1_         = query1_' st
        , withTransaction = withTransaction' st
        }

--------------------------------------------------------------------------------

execute' :: (P.ToRow q) => DBState -> q -> P.Query -> IO ()
execute' st qargs q =
    void (P.execute (db' st) q qargs)

execute_' :: DBState -> P.Query -> IO ()
execute_' st q =
    void (P.execute_ (db' st) q)

query' :: (P.ToRow q, P.FromRow r) => DBState -> q -> P.Query -> IO [r]
query' st qargs q =
    P.query (db' st) q qargs

query_' :: (P.FromRow r) => DBState -> P.Query -> IO [r]
query_' st q =
    P.query_ (db' st) q

query1' :: (P.ToRow q, P.FromRow r) => DBState -> q -> P.Query -> IO (Maybe r)
query1' st qargs q =
    P.query (db' st) q qargs >>= \case
      []  -> return Nothing
      [r] -> return (Just r)
      _   -> error ("dbQuery1: query " ++ show q ++ " returned more than 1 row")

query1_' :: (P.FromRow r) => DBState -> P.Query -> IO (Maybe r)
query1_' st q =
    P.query_ (db' st) q >>= \case
      []  -> return Nothing
      [r] -> return (Just r)
      _   -> error ("dbQuery1_: query " ++ show q ++ " returned more than 1 row")

withTransaction' :: DBState -> IO a -> IO a
withTransaction' st act =
    P.withTransaction (db' st) act

--------------------------------------------------------------------------------
