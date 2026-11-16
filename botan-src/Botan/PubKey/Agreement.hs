module Botan.PubKey.Agreement where

import Botan.Bindings.PubKey
import Botan.Bindings.PubKey.KeyAgreement

import Botan.Internal.Prelude
import Botan.Hash
import Botan.MPI
import Botan.RNG
import Botan.KDF
import Botan.PubKey

import qualified Data.ByteString as ByteString

newtype SharedKey = MkSharedKey { sharedKeyBytes :: ByteString }
    deriving newtype (Eq, Show)

type KeyAgreementSalt = ByteString

instance Memorized BotanPKOpKeyAgreement where
    type Memo BotanPKOpKeyAgreement = Ptr
    type MemRep BotanPKOpKeyAgreement = BotanPKOpKeyAgreementStruct
    withMemo (MkBotanPKOpKeyAgreement ptr) action = action ptr

newtype KeyAgreement = MkKeyAgreement { foreignPtr :: ForeignPtr BotanPKOpKeyAgreementStruct }

instance Memorized KeyAgreement where
    type Memo KeyAgreement = ForeignPtr
    type MemRep KeyAgreement = BotanPKOpKeyAgreementStruct
    withMemo (MkKeyAgreement fptr) action = action fptr

instance BotanObject KeyAgreement where

    type BotanStruct KeyAgreement = BotanPKOpKeyAgreementStruct
    type BotanPtr    KeyAgreement = BotanPKOpKeyAgreement

    toBotanPtr = MkBotanPKOpKeyAgreement
    toBotan    = MkKeyAgreement
    botanFinalizer  = botan_pk_op_key_agreement_destroy

withKeyAgreement :: KeyAgreement -> (BotanPKOpKeyAgreement -> IO a) -> IO a
withKeyAgreement = withBotanPtr @KeyAgreement

keyAgreementDestroy :: KeyAgreement -> IO ()
keyAgreementDestroy = destroyBotan

-- NOTE: Silently uses the system RNG
keyAgreementCreate :: PrivKey -> KDFType -> IO KeyAgreement
keyAgreementCreate sk kdfType = mask_ $
    withPrivKey sk $ \ skPtr ->
    useAsCString (kdfName kdfType) $ \ kdfPtr ->
    createBotan @KeyAgreement $ \ outPtr -> botan_pk_op_key_agreement_create
        outPtr
        skPtr
        (ConstPtr kdfPtr)
        0

-- TODO: KA functions