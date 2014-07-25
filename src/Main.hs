--------------------------------------------------------------------------------

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module Main where

import Control.Applicative ((<$>))
import Data.Char (isHexDigit)
import Data.List (dropWhileEnd)
import Data.Text (Text)
import Network.HTTP.Types (StdMethod (..))
import System.Environment (getEnv)
import System.Exit (ExitCode (..))
import System.IO (BufferMode (..), hSetBuffering, stdout)
import System.Posix.Process (exitImmediately)
import System.Posix.Signals (Handler (..), installHandler, sigTERM)

import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text as T
import qualified Network.HTTP.Types as HTTP
import qualified Network.Wai as WAI
import qualified Network.Wai.Handler.Warp as Warp

import Access (initAccess)
import Auth (initAuth)
import DB (initDB)

--------------------------------------------------------------------------------

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    port <- read <$> getEnv "PORT"
    _ <- installHandler sigTERM (Catch (handleSIGTERM port)) Nothing
    dburl <- getEnv "DATABASE_URL"
    db <- initDB dburl
    _ <- initAuth db
    _ <- initAccess db
    putStrLn ("Listening started on port " ++ show port)
    Warp.run port app

handleSIGTERM :: Int -> IO ()
handleSIGTERM port = do
    putStrLn ("Listening stopped on port " ++ show port)
    exitImmediately ExitSuccess

--------------------------------------------------------------------------------

newtype AccountID = AccountID Text
  deriving (Eq, Ord, Show)

newtype SessionID = SessionID Text
  deriving (Eq, Ord, Show)

toAccountID :: Text -> Maybe AccountID
toAccountID segment
    | T.all isHexDigit segment =
        Just (AccountID segment)
    | otherwise =
        Nothing

toSessionID :: Text -> Maybe SessionID
toSessionID segment
    | T.all isHexDigit segment =
        Just (SessionID segment)
    | otherwise =
        Nothing

--------------------------------------------------------------------------------

app :: WAI.Application
app req respond = do
    let path = dropWhileEnd T.null (WAI.pathInfo req)
    res <- case HTTP.parseMethod (WAI.requestMethod req) of
      Right method ->
        route req path method
      Left _ ->
        badRequestText
    respond res

route :: WAI.Request -> [Text] -> StdMethod -> IO WAI.Response
route req path method = do
    putStrLn ("Path: " ++ show path)
    case path of
      ["accounts"] ->
        case method of
          GET  -> showAllAccounts req
          POST -> createNewAccount req
          _ ->
            methodNotAllowedText
      ["accounts", toAccountID -> Just aid] ->
        case method of
          GET    -> showAccount req aid
          PUT    -> updateAccount req aid
          DELETE -> deleteAccount req aid
          _ ->
            methodNotAllowedText
      ["sessions"] ->
        case method of
          GET  -> showAllSessions req
          POST -> createNewSession req
          _ ->
            methodNotAllowedText
      ["sessions", toSessionID -> Just sid] ->
        case method of
          GET    -> showSession req sid
          PUT    -> updateSession req sid
          DELETE -> deleteSession req sid
          _ ->
            methodNotAllowedText
      _ ->
        badRequestText

--------------------------------------------------------------------------------

showAllAccounts :: WAI.Request -> IO WAI.Response
showAllAccounts req = do
    putStrLn "Showing all accounts"
    okText "All accounts"

createNewAccount :: WAI.Request -> IO WAI.Response
createNewAccount req = do
    putStrLn "Creating new account"
    createdText "New account"

showAccount :: WAI.Request -> AccountID -> IO WAI.Response
showAccount req aid = do
    putStrLn ("Showing account " ++ show aid)
    okText "Account"

updateAccount :: WAI.Request -> AccountID -> IO WAI.Response
updateAccount req aid = do
    putStrLn ("Updating account " ++ show aid)
    noContent

deleteAccount :: WAI.Request -> AccountID -> IO WAI.Response
deleteAccount req aid = do
    putStrLn ("Deleting account " ++ show aid)
    noContent

showAllSessions :: WAI.Request -> IO WAI.Response
showAllSessions req = do
    putStrLn "Showing all sessions"
    okText "All sessions"

createNewSession :: WAI.Request -> IO WAI.Response
createNewSession req = do
    putStrLn "Creating new session"
    createdText "New session"

showSession :: WAI.Request -> SessionID -> IO WAI.Response
showSession req sid = do
    putStrLn ("Showing session " ++ show sid)
    okText "Session"

updateSession :: WAI.Request -> SessionID -> IO WAI.Response
updateSession req sid = do
    putStrLn ("Updating session " ++ show sid)
    noContent

deleteSession :: WAI.Request -> SessionID -> IO WAI.Response
deleteSession req sid = do
    putStrLn ("Deleting session " ++ show sid)
    noContent

--------------------------------------------------------------------------------

okText :: LBS.ByteString -> IO WAI.Response
okText body = do
    putStrLn "Accepting request with status 200"
    text HTTP.ok200 body

createdText :: LBS.ByteString -> IO WAI.Response
createdText body = do
    putStrLn "Accepting request with status 201"
    text HTTP.created201 body

noContent :: IO WAI.Response
noContent = do
    putStrLn "Accepting request with status 204"
    text HTTP.noContent204 ""

badRequestText :: IO WAI.Response
badRequestText = do
    putStrLn "Rejecting request with status 400"
    text HTTP.badRequest400 "Client error: Bad request (400)"

unauthorizedText :: IO WAI.Response
unauthorizedText = do
    putStrLn "Rejecting request with status 401"
    text HTTP.unauthorized401 "Client error: Unauthorized (401)"

methodNotAllowedText :: IO WAI.Response
methodNotAllowedText = do
    putStrLn "Rejecting request with status 405"
    text HTTP.methodNotAllowed405 "Client error: Method not allowed (405)"

text :: HTTP.Status -> LBS.ByteString -> IO WAI.Response
text status body =
    return (WAI.responseLBS status [("Content-Type", "text/plain")] (LBS.append body "\n"))

--------------------------------------------------------------------------------
