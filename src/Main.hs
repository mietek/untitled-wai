--------------------------------------------------------------------------------

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import Control.Applicative ((<$>))
import System.Environment (getEnv)
import System.Exit (ExitCode (..))
import System.IO (BufferMode (..), hSetBuffering, stdout)
import System.Posix.Process (exitImmediately)
import System.Posix.Signals (Handler (..), installHandler, sigTERM)

import qualified Network.HTTP.Types as HTTP
import qualified Network.Wai as WAI
import qualified Network.Wai.Handler.Warp as Warp

import Auth (initAuth)
import DB (initDB)

--------------------------------------------------------------------------------

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    _ <- installHandler sigTERM (Catch handleSIGTERM) Nothing
    port <- read <$> getEnv "PORT"
    dburl <- getEnv "DATABASE_URL"
    db <- initDB dburl
    _ <- initAuth db
    putStrLn ("Listening on " ++ show port)
    Warp.run port app

--------------------------------------------------------------------------------

handleSIGTERM :: IO ()
handleSIGTERM = do
    putStrLn "Exiting"
    exitImmediately ExitSuccess

app :: WAI.Application
app _request respond =
    respond $
      WAI.responseLBS HTTP.status200
        [("Content-Type", "text/plain")]
        "Hello, world!"

--------------------------------------------------------------------------------
