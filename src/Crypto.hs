--------------------------------------------------------------------------------

module Crypto
    ( UnencryptedPassword
    , Password
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

newtype UnencryptedPassword = UnencryptedPassword Text

newtype Password = Password C.EncryptedPass
  deriving (Eq, Show)

instance P.FromField Password where
  fromField f dat =
      Password . C.EncryptedPass <$> P.fromField f dat

instance P.ToField Password where
  toField (Password (C.EncryptedPass p)) =
      P.toField p

--------------------------------------------------------------------------------

encryptPassword :: UnencryptedPassword -> IO Password
encryptPassword (UnencryptedPassword pass) =
    Password <$> C.encryptPassIO' (C.Pass (T.encodeUtf8 pass))

verifyPassword :: UnencryptedPassword -> Password -> Bool
verifyPassword (UnencryptedPassword candidate) (Password pass) =
    C.verifyPass' (C.Pass (T.encodeUtf8 candidate)) pass

--------------------------------------------------------------------------------
