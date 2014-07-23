--------------------------------------------------------------------------------

module Crypto
    ( Pass
    , EncryptedPass
    , toPass
    , encryptPass
    , verifyPass
    )
  where

import Control.Applicative ((<$>))
import Data.Text (Text)

import qualified Crypto.Scrypt as C
import qualified Data.Text.Encoding as T
import qualified Database.PostgreSQL.Simple.FromField as P
import qualified Database.PostgreSQL.Simple.ToField as P

--------------------------------------------------------------------------------

newtype Pass = Pass C.Pass

newtype EncryptedPass = EncryptedPass C.EncryptedPass
  deriving (Eq, Show)

instance P.FromField EncryptedPass where
  fromField f dat =
      EncryptedPass . C.EncryptedPass <$> P.fromField f dat

instance P.ToField EncryptedPass where
  toField (EncryptedPass (C.EncryptedPass p)) =
      P.toField p

--------------------------------------------------------------------------------

toPass :: Text -> Pass
toPass pass =
    Pass (C.Pass (T.encodeUtf8 pass))

encryptPass :: Pass -> IO EncryptedPass
encryptPass (Pass pass) =
    EncryptedPass <$> C.encryptPassIO' pass

verifyPass :: Pass -> EncryptedPass -> Bool
verifyPass (Pass pass) (EncryptedPass encpass) =
    C.verifyPass' pass encpass

--------------------------------------------------------------------------------
