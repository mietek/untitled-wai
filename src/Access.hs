--------------------------------------------------------------------------------

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Access
    ( Access (..)
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

import Auth (Auth (..))
import DB (DB (..), sql)
import DB.Audit (createAudit, createAuditSchema)
import DB.Notify (createNotify)

--------------------------------------------------------------------------------

newtype OrgID = OrgID Int
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow OrgID where
  fromRow = OrgID <$> P.field

data Access = Access
    { checkPriv :: SessionID -> OrgID -> PrivID -> IO Bool
    }

data AccessState = AccessState
    { db'  :: DB
    , auth :: Auth
    }

--------------------------------------------------------------------------------

initAccess :: DB -> Auth -> IO Access
initAccess db auth = do
    createAccessSchema db
    let
      st = AccessState
        { db'   = db
        , auth' = auth
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
          createPerformsTable db
          createIncludesTable db

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

createPerformsTable :: DB -> IO ()
createPerformsTable db = do
    execute_ db [sql|
      CREATE TABLE performs
        ( actor_id   integer NOT NULL REFERENCES actors
        , role_id    integer NOT NULL REFERENCES roles
        , org_id     integer NOT NULL REFERENCES orgs
        , UNIQUE (actor_id, role_id, org_id)
        )
    |]
    createAudit db "performs"

createIncludesTable :: DB -> IO ()
createIncludesTable db = do
    execute_ db [sql|
      CREATE TABLE includes
        ( role_id    integer NOT NULL REFERENCES roles
        , priv_id    integer NOT NULL REFERENCES privs
        , UNIQUE (role_id, priv_id)
        )
    |]
    createAudit db "includes"

--------------------------------------------------------------------------------

checkPriv' :: AccessState -> SessionID -> OrgID -> PrivID -> IO Bool
checkPriv' st sid oid pid =
    query1 (db' st) () [sql|
      SELECT TRUE
      FROM performs
      NATURAL JOIN actors
      NATURAL JOIN sessions
      WHERE session_id = ?
    |]

--------------------------------------------------------------------------------
