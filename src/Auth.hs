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
import GHC.Generics (Generic)

import qualified Database.PostgreSQL.Simple as P
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.FromRow as P
import qualified Database.PostgreSQL.Simple.ToField as P

import Crypto (Pass, encryptPass, verifyPass)
import DB (DB (..), sql)
import DB.Audit (createAudit)
import Utils (EmailAddress, Name)

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
    { createActor     :: EmailAddress -> Pass -> Name -> IO (Maybe ActorID)
    , deleteActor     :: ActorID -> IO ()
    , findActor       :: EmailAddress -> IO (Maybe ActorID)
    , resetPass       :: ActorID -> Pass -> IO ()
    , createSession   :: EmailAddress -> Pass -> IO (Maybe SessionID)
    , deleteSession   :: SessionID -> IO ()
    , getActor        :: SessionID -> IO (Maybe ActorID)
    , getEmailAddress :: SessionID -> IO (Maybe EmailAddress)
    , getName         :: SessionID -> IO (Maybe Name)
    , setEmailAddress :: SessionID -> Pass -> EmailAddress -> IO (Maybe ())
    , setPass         :: SessionID -> Pass -> Pass -> IO (Maybe ())
    , setName         :: SessionID -> Name -> IO ()
    }

data AuthState = AuthState
    { db' :: DB
    }

--------------------------------------------------------------------------------

initAuth :: DB -> IO Auth
initAuth db = do
    createAuthSchema db
    let
      st = AuthState
        { db' = db
        }
    return $ Auth
      { createActor     = createActor' st
      , deleteActor     = deleteActor' st
      , findActor       = findActor' st
      , resetPass       = resetPass' st
      , createSession   = createSession' st
      , deleteSession   = deleteSession' st
      , getActor        = getActor' st
      , getEmailAddress = getEmailAddress' st
      , getName         = getName' st
      , setEmailAddress = setEmailAddress' st
      , setPass         = setPass' st
      , setName         = setName' st
      }

--------------------------------------------------------------------------------

createAuthSchema :: DB -> IO ()
createAuthSchema db =
    withTransaction db $
      query1_ db [sql|
        SELECT TRUE FROM pg_tables WHERE tablename = 'actors'
      |] >>= \case
        Just ([True]) -> return ()
        _ -> do
          putStrLn "Creating auth schema"
          execute_ db [sql|
            CREATE EXTENSION hstore
          |]
          execute_ db [sql|
            CREATE EXTENSION pgcrypto
          |]
          createActorsTable db
          createSessionsTable db

createActorsTable :: DB -> IO ()
createActorsTable db = do
    execute_ db [sql|
      CREATE TABLE actors
        ( actor_id            serial PRIMARY KEY
        , actor_email_address text   NOT NULL UNIQUE
        , actor_pass          text   NOT NULL
        , actor_name          text   NOT NULL
        )
    |]
    createAudit db "actors"

createSessionsTable :: DB -> IO ()
createSessionsTable db = do
    execute_ db [sql|
      CREATE TABLE sessions
        ( session_id bytea   PRIMARY KEY DEFAULT encode(gen_random_bytes(16), 'hex')
        , actor_id   integer NOT NULL REFERENCES actors
        )
    |]
    execute_ db [sql|
      CREATE INDEX ON sessions (actor_id)
    |]
    createAudit db "sessions"

--------------------------------------------------------------------------------

createActor' :: AuthState -> EmailAddress -> Pass -> Name -> IO (Maybe ActorID)
createActor' st newemail newpass newname = do
    newencpass <- encryptPass newpass
    query1 (db' st) (newemail, newencpass, newname) [sql|
      INSERT INTO actors (actor_email_address, actor_pass, actor_name)
      VALUES (?, ?, ?)
      RETURNING actor_id
    |]

deleteActor' :: AuthState -> ActorID -> IO ()
deleteActor' st aid =
    withTransaction (db' st) $ do
      execute (db' st) [aid] [sql|
        DELETE FROM actors
        WHERE actor_id = ?
      |]
      execute (db' st) [aid] [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
      |]
      execute (db' st) [aid] [sql|
        DELETE FROM performs
        WHERE perform_actor_id = ?
      |]

findActor' :: AuthState -> EmailAddress -> IO (Maybe ActorID)
findActor' st email =
    query1 (db' st) [email] [sql|
      SELECT actor_id
      FROM actors
      WHERE actor_email_address = ?
    |]

resetPass' :: AuthState -> ActorID -> Pass -> IO ()
resetPass' st aid newpass = do
    newencpass <- encryptPass newpass
    withTransaction (db' st) $ do
      execute (db' st) (newencpass, aid) [sql|
        UPDATE actors
        SET actor_pass = ?
        WHERE actor_id = ?
      |]
      execute (db' st) [aid] [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
      |]

createSession' :: AuthState -> EmailAddress -> Pass -> IO (Maybe SessionID)
createSession' st email pass =
    withFoundVerifiedActor' st email pass $ \aid ->
      query1 (db' st) [aid] [sql|
        INSERT INTO sessions (actor_id)
        VALUES (?)
        RETURNING session_id
      |]

deleteSession' :: AuthState -> SessionID -> IO ()
deleteSession' st sid =
    execute (db' st) [sid] [sql|
      DELETE FROM sessions
      WHERE session_id = ?
    |]

getActor' :: AuthState -> SessionID -> IO (Maybe ActorID)
getActor' st sid =
    query1 (db' st) [sid] [sql|
      SELECT actor_id
      FROM sessions
      WHERE session_id = ?
    |]

getEmailAddress' :: AuthState -> SessionID -> IO (Maybe EmailAddress)
getEmailAddress' st sid =
    query1 (db' st) [sid] [sql|
      SELECT actor_email_address
      FROM sessions
      NATURAL JOIN actors
      WHERE session_id = ?
    |]

getName' :: AuthState -> SessionID -> IO (Maybe Name)
getName' st sid =
    query1 (db' st) [sid] [sql|
      SELECT actor_email_name
      FROM sessions
      NATURAL JOIN actors
      WHERE session_id = ?
    |]

setEmailAddress' :: AuthState -> SessionID -> Pass -> EmailAddress -> IO (Maybe ())
setEmailAddress' st sid pass newemail =
    withVerifiedActor' st sid pass $ \aid -> do
      execute (db' st) (newemail, aid) [sql|
        UPDATE actors
        SET actor_email_address = ?
        WHERE actor_id = ?
      |]
      execute (db' st) (aid, sid) [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
        AND session_id <> ?
      |]
      return (Just ())

setPass' :: AuthState -> SessionID -> Pass -> Pass -> IO (Maybe ())
setPass' st sid pass newpass = do
    newencpass <- encryptPass newpass
    withVerifiedActor' st sid pass $ \aid -> do
      execute (db' st) (newencpass, aid) [sql|
        UPDATE actors
        SET actor_pass = ?
        WHERE actor_id = ?
      |]
      execute (db' st) (aid, sid) [sql|
        DELETE FROM sessions
        WHERE actor_id = ?
        AND session_id <> ?
      |]
      return (Just ())

setName' :: AuthState -> SessionID -> Name -> IO ()
setName' st sid newname =
    execute (db' st) (newname, sid) [sql|
      UPDATE actors
      SET actor_name = ?
      FROM sessions
      NATURAL JOIN actors
      WHERE session_id = ?
    |]

--------------------------------------------------------------------------------

withFoundVerifiedActor' :: AuthState -> EmailAddress -> Pass -> (ActorID -> IO (Maybe a)) -> IO (Maybe a)
withFoundVerifiedActor' st email pass act =
    withTransaction (db' st) $
      query1 (db' st) [email] [sql|
        SELECT actor_id, actor_pass
          FROM actors
          WHERE actor_email_address = ?
      |] >>= \case
        Just (aid, encpass) | verifyPass pass encpass -> act aid
        _ -> return Nothing

withVerifiedActor' :: AuthState -> SessionID -> Pass -> (ActorID -> IO (Maybe a)) -> IO (Maybe a)
withVerifiedActor' st sid pass act =
    withTransaction (db' st) $
      query1 (db' st) [sid] [sql|
        SELECT actor_id, actor_pass
          FROM sessions
          NATURAL JOIN actors
          WHERE session_id = ?
      |] >>= \case
        Just (aid, encpass) | verifyPass pass encpass -> act aid
        _ -> return Nothing

--------------------------------------------------------------------------------
