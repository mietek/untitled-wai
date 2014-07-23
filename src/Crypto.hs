--------------------------------------------------------------------------------

module Crypto
    ( Password
    , EncryptedPassword
    , toPassword
    , encryptPassword
    , verifyPassword
    )
  where

import Control.Applicative ((<$>))
import Data.Text (Text)

import qualified Crypto.Scrypt as C
import qualified Data.Text.Encoding as T
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.ToField as P

--------------------------------------------------------------------------------

newtype Password = Password C.Pass

newtype EncryptedPassword = EncryptedPassword C.EncryptedPass
  deriving (Eq, Show)

instance P.FromField EncryptedPassword where
  fromField f dat =
      EncryptedPassword . C.EncryptedPass <$> P.fromField f dat

instance P.ToField EncryptedPassword where
  toField (EncryptedPassword (C.EncryptedPass p)) =
      P.toField p

--------------------------------------------------------------------------------

toPassword :: Text -> Password
toPassword pass =
    Password (C.Pass (T.encodeUtf8 pass))

encryptPassword :: Password -> IO EncryptedPassword
encryptPassword (Password pass) =
    EncryptedPassword <$> C.encryptPassIO' pass

verifyPassword :: Password -> EncryptedPassword -> Bool
verifyPassword (Password unpass) (EncryptedPassword pass) =
    C.verifyPass' unpass pass

--------------------------------------------------------------------------------
