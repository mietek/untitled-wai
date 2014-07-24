--------------------------------------------------------------------------------

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Access
    ( OrgID
    , RoleID
    , PrivID
    , Access (..)
    , initAccess
    )
  where

import Control.Applicative ((<$>))
import Data.Hashable (Hashable)
import GHC.Generics (Generic)

import qualified Database.PostgreSQL.Simple as P
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.FromRow as P
import qualified Database.PostgreSQL.Simple.ToField as P

import Auth (SessionID)
import DB (DB (..), sql)
import DB.Audit (createAudit)

--------------------------------------------------------------------------------

newtype OrgID = OrgID Int
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow OrgID where
  fromRow = OrgID <$> P.field

newtype RoleID = RoleID Int
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow RoleID where
  fromRow = RoleID <$> P.field

newtype PrivID = PrivID Int
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow PrivID where
  fromRow = PrivID <$> P.field

data Access = Access
    { checkPriv :: SessionID -> OrgID -> PrivID -> IO Bool
    }

data AccessState = AccessState
    { db'  :: DB
    }

--------------------------------------------------------------------------------

initAccess :: DB -> IO Access
initAccess db = do
    createAccessSchema db
    let
      st = AccessState
        { db'   = db
        }
    return $ Access
      { checkPriv = checkPriv' st
      }

--------------------------------------------------------------------------------

createAccessSchema :: DB -> IO ()
createAccessSchema db =
    withTransaction db $
      query1_ db [sql|
        SELECT TRUE FROM pg_tables WHERE tablename = 'orgs'
      |] >>= \case
        Just ([True]) -> return ()
        _ -> do
          putStrLn "Creating access schema"
          execute_ db [sql|
            CREATE EXTENSION pgcrypto
          |]
          createOrgsTable db
          createRolesTable db
          createPrivsTable db
          createPerformingAtTable db
          createIncludingTable db

createOrgsTable :: DB -> IO ()
createOrgsTable db = do
    execute_ db [sql|
      CREATE TABLE orgs
        ( org_id   serial PRIMARY KEY
        , org_name text   NOT NULL
        )
    |]
    createAudit db "orgs"

createRolesTable :: DB -> IO ()
createRolesTable db = do
    execute_ db [sql|
      CREATE TABLE roles
        ( role_id   serial PRIMARY KEY
        , role_name text   NOT NULL UNIQUE
        )
    |]
    createAudit db "roles"

createPrivsTable :: DB -> IO ()
createPrivsTable db = do
    execute_ db [sql|
      CREATE TABLE privs
        ( priv_id   serial PRIMARY KEY
        , priv_name text   NOT NULL UNIQUE
        )
    |]
    createAudit db "privs"

createPerformingAtTable :: DB -> IO ()
createPerformingAtTable db = do
    execute_ db [sql|
      CREATE TABLE performing_at
        ( actor_id   integer NOT NULL REFERENCES actors
        , role_id    integer NOT NULL REFERENCES roles
        , org_id     integer NOT NULL REFERENCES orgs
        , UNIQUE (actor_id, role_id, org_id)
        )
    |]
    createAudit db "performs"

createIncludingTable :: DB -> IO ()
createIncludingTable db = do
    execute_ db [sql|
      CREATE TABLE including
        ( role_id    integer NOT NULL REFERENCES roles
        , priv_id    integer NOT NULL REFERENCES privs
        , UNIQUE (role_id, priv_id)
        )
    |]
    createAudit db "includes"

--------------------------------------------------------------------------------

checkPriv' :: AccessState -> SessionID -> OrgID -> PrivID -> IO Bool
checkPriv' st sid oid pid =
    query1 (db' st) (sid, oid, pid) [sql|
      SELECT DISTINCT TRUE
      FROM sessions
      NATURAL JOIN actors
      NATURAL JOIN performing_at
      NATURAL JOIN orgs
      NATURAL JOIN roles
      NATURAL JOIN including
      NATURAL JOIN privs
      WHERE session_id = ?
      AND org_id = ?
      AND priv_id = ?
    |] >>= \case
      Just ([True]) -> return True
      _ -> return False

--------------------------------------------------------------------------------
