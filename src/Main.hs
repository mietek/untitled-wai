--------------------------------------------------------------------------------

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import Control.Applicative ((<$>))
import System.Environment (getEnv)

import qualified Network.HTTP.Types as HTTP
import qualified Network.Wai as WAI
import qualified Network.Wai.Handler.Warp as Warp

import Auth (initAuth)
import DB (DB (..), initDB, sql)

--------------------------------------------------------------------------------

main :: IO ()
main = do
    port <- read <$> getEnv "PORT"
    dburl <- getEnv "DATABASE_URL"
    db <- initDB dburl
    execute_ db [sql|
      CREATE EXTENSION hstore
    |]
    execute_ db [sql|
      CREATE EXTENSION pgcrypto
    |]
    _ <- initAuth db
    putStrLn ("Listening on " ++ show port)
    Warp.run port app

--------------------------------------------------------------------------------

app :: WAI.Application
app _request respond =
    respond $
      WAI.responseLBS HTTP.status200
        [("Content-Type", "text/plain")]
        "Hello, world!"

--------------------------------------------------------------------------------
