module Botan.PubKey.Encapsulation where

import Botan.Bindings.PubKey
import Botan.Bindings.PubKey.KeyEncapsulation

import Botan.Internal.Prelude
import Botan.Hash
import Botan.MPI
import Botan.RNG
import Botan.KDF
import Botan.PubKey

newtype EncapsulatedKey = MkEncapsulatedKey { encapsulatedKeyBytes :: ByteString }
    deriving newtype (Eq, Show)

type KEMSalt = ByteString

instance Memorized BotanPKOpKEMEncrypt where
    type Memo BotanPKOpKEMEncrypt = Ptr
    type MemRep BotanPKOpKEMEncrypt = BotanPKOpKEMEncryptStruct
    withMemo (MkBotanPKOpKEMEncrypt ptr) action = action ptr

instance Memorized BotanPKOpKEMDecrypt where
    type Memo BotanPKOpKEMDecrypt = Ptr
    type MemRep BotanPKOpKEMDecrypt = BotanPKOpKEMDecryptStruct
    withMemo (MkBotanPKOpKEMDecrypt ptr) action = action ptr

newtype KEMEncrypt = MkKEMEncrypt { foreignPtr :: ForeignPtr BotanPKOpKEMEncryptStruct }

instance Memorized KEMEncrypt where
    type Memo KEMEncrypt = ForeignPtr
    type MemRep KEMEncrypt = BotanPKOpKEMEncryptStruct
    withMemo (MkKEMEncrypt fptr) action = action fptr

instance BotanObject KEMEncrypt where

    type BotanStruct KEMEncrypt = BotanPKOpKEMEncryptStruct
    type BotanPtr    KEMEncrypt = BotanPKOpKEMEncrypt

    toBotanPtr = MkBotanPKOpKEMEncrypt
    toBotan    = MkKEMEncrypt
    botanFinalizer  = botan_pk_op_kem_encrypt_destroy

newtype KEMDecrypt = MkKEMDecrypt { foreignPtr :: ForeignPtr BotanPKOpKEMDecryptStruct }

instance Memorized KEMDecrypt where
    type Memo KEMDecrypt = ForeignPtr
    type MemRep KEMDecrypt = BotanPKOpKEMDecryptStruct
    withMemo (MkKEMDecrypt fptr) action = action fptr

instance BotanObject KEMDecrypt where

    type BotanStruct KEMDecrypt = BotanPKOpKEMDecryptStruct
    type BotanPtr    KEMDecrypt = BotanPKOpKEMDecrypt

    toBotanPtr = MkBotanPKOpKEMDecrypt
    toBotan    = MkKEMDecrypt
    botanFinalizer  = botan_pk_op_kem_decrypt_destroy

withKEMEncrypt :: KEMEncrypt -> (BotanPKOpKEMEncrypt -> IO a) -> IO a
withKEMEncrypt = withBotanPtr @KEMEncrypt

kemEncryptDestroy :: KEMEncrypt -> IO ()
kemEncryptDestroy = destroyBotan

kemEncryptCreate :: PubKey -> KDFType -> IO KEMEncrypt
kemEncryptCreate pk kdfType = mask_ $
    withPubKey pk $ \ pkPtr ->
    useAsCString (kdfName kdfType) $ \ kdfPtr ->
    createBotan @KEMEncrypt $ \ outPtr -> botan_pk_op_kem_encrypt_create
        outPtr
        pkPtr
        (ConstPtr kdfPtr)

withKEMDecrypt :: KEMDecrypt -> (BotanPKOpKEMDecrypt -> IO a) -> IO a
withKEMDecrypt = withBotanPtr @KEMDecrypt

kemDecryptDestroy :: KEMDecrypt -> IO ()
kemDecryptDestroy = destroyBotan

kemDecryptCreate :: PrivKey -> KDFType -> IO KEMDecrypt
kemDecryptCreate sk kdfType = mask_ $
    withPrivKey sk $ \ skPtr ->
    useAsCString (kdfName kdfType) $ \ kdfPtr ->
    createBotan @KEMDecrypt $ \ outPtr -> botan_pk_op_kem_decrypt_create
        outPtr
        skPtr
        (ConstPtr kdfPtr)