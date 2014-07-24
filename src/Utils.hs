--------------------------------------------------------------------------------

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Utils
    ( EmailAddress
    , UniqueName
    , Name
    )
  where

import Control.Applicative ((<$>))
import Data.Hashable (Hashable)
import Data.Text (Text)
import GHC.Generics (Generic)

import qualified Database.PostgreSQL.Simple as P
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.FromRow as P
import qualified Database.PostgreSQL.Simple.ToField as P

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
