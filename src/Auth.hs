--------------------------------------------------------------------------------

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Auth
    ( ActorID
    , SessionID
    , Auth (..)
    , initAuth
    )
  where

import Control.Applicative ((<$>))
import Data.ByteString (ByteString)
import Data.Hashable (Hashable)
import Data.Text (Text)
import GHC.Generics (Generic)

import qualified Database.PostgreSQL.Simple as P
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.FromRow as P
import qualified Database.PostgreSQL.Simple.ToField as P

import Crypto (EncryptedPassword, Password, encryptPassword, verifyPassword)
import DB (DB (..), sql)
import DB.Audit (createAudit, initAuditSchema)
import DB.Notify (createNotify)

--------------------------------------------------------------------------------

newtype EmailAddress = EmailAddress Text
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow EmailAddress where
  fromRow = EmailAddress <$> P.field

newtype UniqueName = UniqueName Text
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow UniqueName where
  fromRow = UniqueName <$> P.field

newtype Name = Name Text
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow Name where
  fromRow = Name <$> P.field

--------------------------------------------------------------------------------

newtype ActorID = ActorID Int
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow ActorID where
  fromRow = ActorID <$> P.field

newtype SessionID = SessionID ByteString
  deriving (Eq, Generic, Hashable, Ord, P.FromField, P.ToField, Show)

instance P.FromRow SessionID where
  fromRow = SessionID <$> P.field

data Auth = Auth
    { createActor     :: EmailAddress -> Password -> Name -> IO (Maybe ActorID)
    , deleteActor     :: ActorID -> IO ()
    , findActor       :: EmailAddress -> IO (Maybe ActorID)
    , resetPassword   :: ActorID -> Password -> IO ()
    , createSession   :: EmailAddress -> Password -> IO (Maybe SessionID)
    , deleteSession   :: SessionID -> IO ()
    , getActor        :: SessionID -> IO (Maybe ActorID)
    , getEmailAddress :: SessionID -> IO (Maybe EmailAddress)
    , getName         :: SessionID -> IO (Maybe Name)
    , setEmailAddress :: SessionID -> Password -> EmailAddress -> IO Bool
    , setPassword     :: SessionID -> Password -> Password -> IO Bool
    , setName         :: SessionID -> Name -> IO ()
    }

data AuthState = AuthState
    { db' :: DB
    }

--------------------------------------------------------------------------------

initAuth :: DB -> IO Auth
initAuth db = do
    initAuditSchema db
    initAuthSchema db
    let
      st = AuthState
        { db' = db
        }
    return $ Auth
      { createActor     = createActor' st
      , deleteActor     = deleteActor' st
      , findActor       = findActor' st
      , resetPassword   = resetPassword' st
      , createSession   = createSession' st
      , deleteSession   = deleteSession' st
      , getActor        = getActor' st
      , getEmailAddress = getEmailAddress' st
      , getName         = getName' st
      , setEmailAddress = setEmailAddress' st
      , setPassword     = setPassword' st
      , setName         = setName' st
      }

--------------------------------------------------------------------------------

initAuthSchema :: DB -> IO ()
initAuthSchema db =
    withTransaction db $
      query1_ db [sql|
        SELECT EXISTS (SELECT * FROM pg_extension WHERE extname = 'pgcrypto')
      |] >>= \case
        Just (P.Only True) -> return ()
        _ -> do
          execute_ db [sql|
            CREATE EXTENSION pgcrypto
          |]
          createActorsTable db
          createSessionsTable db
          createOrganisationsTable db
          createRolesTable db
          createPrivilegesTable db
          createPerformsTable db
          createIncludesTable db

createActorsTable :: DB -> IO ()
createActorsTable db = do
    execute_ db [sql|
      CREATE TABLE actors
        ( actor_id            serial PRIMARY KEY
        , actor_email_address text   NOT NULL UNIQUE
        , actor_password      text   NOT NULL
        , actor_name          text   NOT NULL
        )
    |]
    createAudit db "actors"
    createNotify db "actors" "actor_id"

createSessionsTable :: DB -> IO ()
createSessionsTable db = do
    execute_ db [sql|
      CREATE TABLE sessions
        ( session_id bytea   PRIMARY KEY DEFAULT gen_random_bytes(16)
        , actor_id   integer NOT NULL REFERENCES actors
        )
    |]
    execute_ db [sql|
      CREATE INDEX ON sessions (actor_id)
    |]
    createAudit db "sessions"
    createNotify db "sessions" "session_id"

createOrganisationsTable :: DB -> IO ()
createOrganisationsTable db = do
    execute_ db [sql|
      CREATE TABLE organisations
        ( organisation_id   serial PRIMARY KEY
        , organisation_name text   NOT NULL
        )
    |]
    createAudit db "organisations"
    createNotify db "organisations" "organisation_id"

createRolesTable :: DB -> IO ()
createRolesTable db = do
    execute_ db [sql|
      CREATE TABLE roles
        ( role_id   serial PRIMARY KEY
        , role_name text   NOT NULL UNIQUE
        )
    |]
    createAudit db "roles"
    createNotify db "roles" "role_id"

createPrivilegesTable :: DB -> IO ()
createPrivilegesTable db = do
    execute_ db [sql|
      CREATE TABLE privileges
        ( privilege_id   serial PRIMARY KEY
        , privilege_name text   NOT NULL UNIQUE
        )
    |]
    createAudit db "privileges"
    createNotify db "privileges" "privilege_id"

createPerformsTable :: DB -> IO ()
createPerformsTable db = do
    execute_ db [sql|
      CREATE TABLE performs
        ( perform_id      serial  PRIMARY KEY
        , actor_id        integer NOT NULL REFERENCES actors
        , role_id         integer NOT NULL REFERENCES roles
        , organisation_id integer NOT NULL REFERENCES organisations
        , UNIQUE (actor_id, role_id, organisation_id)
        )
    |]
    createAudit db "performs"
    createNotify db "performs" "perform_id"

createIncludesTable :: DB -> IO ()
createIncludesTable db = do
    execute_ db [sql|
      CREATE TABLE includes
        ( include_id   serial  PRIMARY KEY
        , role_id      integer NOT NULL REFERENCES roles
        , privilege_id integer NOT NULL REFERENCES privileges
        , UNIQUE (role_id, privilege_id)
        )
    |]
    createAudit db "includes"
    createNotify db "includes" "include_id"

--------------------------------------------------------------------------------

createActor' :: AuthState -> EmailAddress -> Password -> Name -> IO (Maybe ActorID)
createActor' st newemail newunpass newname = do
    newpass <- encryptPassword newunpass
    query1 (db' st) (newemail :: EmailAddress, newpass :: EncryptedPassword, newname :: Name) [sql|
      INSERT INTO actors (actor_email_address, actor_password, actor_name)
      VALUES (?, ?, ?)
      RETURNING actor_id
    |]

deleteActor' :: AuthState -> ActorID -> IO ()
deleteActor' st aid =
    withTransaction (db' st) $ do
      execute (db' st) [aid :: ActorID] [sql|
        DELETE FROM actors
        WHERE actor_id = ?
      |]
      execute (db' st) [aid :: ActorID] [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
      |]
      execute (db' st) [aid :: ActorID] [sql|
        DELETE FROM performs
        WHERE perform_actor_id = ?
      |]

findActor' :: AuthState -> EmailAddress -> IO (Maybe ActorID)
findActor' st email =
    query1 (db' st) [email :: EmailAddress] [sql|
      SELECT actor_id
      FROM actors
      WHERE actor_email_address = ?
    |]

resetPassword' :: AuthState -> ActorID -> Password -> IO ()
resetPassword' st aid newunpass = do
    newpass <- encryptPassword newunpass
    withTransaction (db' st) $ do
      execute (db' st) (newpass :: EncryptedPassword, aid :: ActorID) [sql|
        UPDATE actors
        SET actor_password = ?
        WHERE actor_id = ?
      |]
      execute (db' st) [aid :: ActorID] [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
      |]

createSession' :: AuthState -> EmailAddress -> Password -> IO (Maybe SessionID)
createSession' st email unpass =
    withTransaction (db' st) $
      query1 (db' st) [email :: EmailAddress] [sql|
        SELECT actor_id, actor_password
          FROM actors
          WHERE actor_email_address = ?
      |] >>= \case
        Just (aid, pass) | verifyPassword unpass pass ->
          query1 (db' st) [aid :: ActorID] [sql|
            INSERT INTO sessions (actor_id)
            VALUES (?)
            RETURNING session_id
          |]
        _ -> return Nothing

deleteSession' :: AuthState -> SessionID -> IO ()
deleteSession' st sid =
    execute (db' st) [sid :: SessionID] [sql|
      DELETE FROM sessions
      WHERE session_id = ?
    |]

getActor' :: AuthState -> SessionID -> IO (Maybe ActorID)
getActor' st sid =
    query1 (db' st) [sid :: SessionID] [sql|
      SELECT actors_id
      FROM sessions
      WHERE session_id = ?
    |]

getEmailAddress' :: AuthState -> SessionID -> IO (Maybe EmailAddress)
getEmailAddress' st sid =
    query1 (db' st) [sid :: SessionID] [sql|
      SELECT actor_email_address
      FROM actors
      NATURAL JOIN sessions
      WHERE session_id = ?
    |]

getName' :: AuthState -> SessionID -> IO (Maybe Name)
getName' st sid =
    query1 (db' st) [sid :: SessionID] [sql|
      SELECT actor_email_name
      FROM actors
      NATURAL JOIN sessions
      WHERE session_id = ?
    |]

setEmailAddress' :: AuthState -> SessionID -> Password -> EmailAddress -> IO Bool
setEmailAddress' st sid unpass newemail =
    withTransaction (db' st) $
      query1 (db' st) [sid :: SessionID] [sql|
        SELECT actor_id, actor_password
          FROM actors
          NATURAL JOIN sessions
          WHERE session_id = ?
      |] >>= \case
        Just (aid, pass) | verifyPassword unpass pass -> do
          execute (db' st) (newemail :: EmailAddress, aid :: ActorID) [sql|
            UPDATE actors
            SET actor_email_address = ?
            WHERE actor_id = ?
          |]
          execute (db' st) (aid :: ActorID, sid :: SessionID) [sql|
            DELETE FROM sessions
            WHERE actor_id = ?
            AND session_id <> ?
          |]
          return True
        _ -> return False

setPassword' :: AuthState -> SessionID -> Password -> Password -> IO Bool
setPassword' st sid unpass newunpass = do
    newpass <- encryptPassword newunpass
    withTransaction (db' st) $
      query1 (db' st) [sid :: SessionID] [sql|
        SELECT actor_id, actor_password
          FROM actors
          NATURAL JOIN sessions
          WHERE session_id = ?
      |] >>= \case
        Just (aid, pass) | verifyPassword unpass pass -> do
          execute (db' st) (newpass :: EncryptedPassword, aid :: ActorID) [sql|
            UPDATE actors
            SET actor_password = ?
            WHERE actor_id = ?
          |]
          execute (db' st) (aid :: ActorID, sid :: SessionID) [sql|
            DELETE FROM sessions
            WHERE actor_id = ?
            AND session_id <> ?
          |]
          return True
        _ -> return False

setName' :: AuthState -> SessionID -> Name -> IO ()
setName' st sid newname =
    execute (db' st) (newname :: Name, sid :: SessionID) [sql|
      UPDATE actors
      SET actor_name = ?
      FROM actors
      NATURAL JOIN sessions
      WHERE session_id = ?
    |]

--------------------------------------------------------------------------------
