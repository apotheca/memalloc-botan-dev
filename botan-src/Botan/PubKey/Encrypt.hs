module Botan.PubKey.Encrypt
(   pkEncrypt
,   pkDecrypt
,   Ciphertext(..)
,   EME(..)
,   emeName
,   Encrypt(..)
,   Decrypt(..)
,   withEncrypt
,   encryptCreate
,   encryptGetOutputLength
,   encrypt
,   withDecrypt
,   decryptCreate
,   decryptGetOutputLength
,   decrypt
) where

import Botan.Bindings.PubKey
import Botan.Bindings.PubKey.Decrypt
import Botan.Bindings.PubKey.Encrypt

import Botan.Internal.Prelude
import Botan.Hash
import Botan.MPI
import Botan.RNG
import Botan.PubKey

import qualified Data.ByteString as ByteString

-- Main interface

-- NOTE: IO because non-deterministic
pkEncrypt :: PubKey -> EME -> ByteString -> IO Ciphertext
pkEncrypt pk eme ptext = do
    enc <- encryptCreate pk eme
    encrypt enc userThreadsafeRNG ptext

pkDecrypt :: PrivKey -> EME -> Ciphertext -> ByteString
pkDecrypt sk eme ctext = doIO $ do
    dec <- decryptCreate sk eme
    decrypt dec ctext

-- Data types

-- TODO: Rename PKCiphertext
newtype Ciphertext = MkCiphertext { ciphertextBytes :: ByteString }
    deriving newtype (Eq, Show)

-- Algorithm type

-- TODO: Rename PKEncryptParams / -Type?
data EME
    = EME_RAW
    | EME_PKCS1_v1_5
    | EME_OAEP HashType
    -- TODO: | EME_OAEP_MGF HashType MGFType
    | EME_HASH HashType
    | EME_SM2EncParam HashType
    deriving stock (Show, Eq, Ord)

emeName :: EME -> ByteString
emeName EME_RAW             = BOTAN_EME_RAW
emeName EME_PKCS1_v1_5      = BOTAN_EME_PKCS1_v1_5
emeName (EME_OAEP h)        = BOTAN_EME_OAEP /$ hashName h
emeName (EME_HASH h)        = hashName h
emeName (EME_SM2EncParam h) = hashName h

-- Algorithms

-- Bindings instance

instance Memorized BotanPKOpEncrypt where
    type Memo BotanPKOpEncrypt = Ptr
    type MemRep BotanPKOpEncrypt = BotanPKOpEncryptStruct
    withMemo (MkBotanPKOpEncrypt ptr) action = action ptr

instance Memorized BotanPKOpDecrypt where
    type Memo BotanPKOpDecrypt = Ptr
    type MemRep BotanPKOpDecrypt = BotanPKOpDecryptStruct
    withMemo (MkBotanPKOpDecrypt ptr) action = action ptr

-- Context objects

-- TODO: Maybe rename PKOpEncrypt?
newtype Encrypt = MkEncrypt { foreignPtr :: ForeignPtr BotanPKOpEncryptStruct }

instance Memorized Encrypt where
    type Memo Encrypt = ForeignPtr
    type MemRep Encrypt = BotanPKOpEncryptStruct
    withMemo (MkEncrypt fptr) action = action fptr

instance BotanObject Encrypt where

    type BotanStruct Encrypt = BotanPKOpEncryptStruct
    type BotanPtr    Encrypt = BotanPKOpEncrypt

    toBotanPtr = MkBotanPKOpEncrypt
    toBotan    = MkEncrypt
    botanFinalizer  = botan_pk_op_encrypt_destroy

-- TODO: Maybe rename PKOpDecrypt?
newtype Decrypt = MkDecrypt { foreignPtr :: ForeignPtr BotanPKOpDecryptStruct }

instance Memorized Decrypt where
    type Memo Decrypt = ForeignPtr
    type MemRep Decrypt = BotanPKOpDecryptStruct
    withMemo (MkDecrypt fptr) action = action fptr

instance BotanObject Decrypt where

    type BotanStruct Decrypt = BotanPKOpDecryptStruct
    type BotanPtr    Decrypt = BotanPKOpDecrypt

    toBotanPtr = MkBotanPKOpDecrypt
    toBotan    = MkDecrypt
    botanFinalizer  = botan_pk_op_decrypt_destroy

-- Bindings / IO interface

withEncrypt :: Encrypt -> (BotanPKOpEncrypt -> IO a) -> IO a
withEncrypt = withBotanPtr @Encrypt

encryptDestroy :: Encrypt -> IO ()
encryptDestroy = destroyBotan

encryptCreate :: PubKey -> EME -> IO Encrypt
encryptCreate pk eme = mask_ $
    withPubKey pk $ \ pkPtr ->
    useAsCString (emeName eme) $ \ paddingPtr ->
    createBotan @Encrypt $ \ outPtr -> botan_pk_op_encrypt_create
        outPtr
        pkPtr
        (ConstPtr paddingPtr)
        0

-- | Output length (in bytes) of encrypting a plaintext of the given length
encryptGetOutputLength :: Encrypt -> Int -> IO Int
encryptGetOutputLength enc ptextLen = mask_ $
    withEncrypt enc $ \ encPtr ->
    alloca $ \ szPtr -> do
        throwBotanIfNegative_ $
            botan_pk_op_encrypt_output_length encPtr (fromIntegral ptextLen) szPtr
        fromIntegral <$> peek szPtr

encrypt :: Encrypt -> RNG -> ByteString -> IO Ciphertext
encrypt enc rng ptext = mask_ $
    withEncrypt enc $ \ encPtr ->
    withRNG rng $ \ rngPtr ->
    withPtrLen ptext $ \ ptextPtr ptextLen -> do
        sz <- encryptGetOutputLength enc ptextLen
        alloca $ \ szPtr -> do
            poke szPtr (fromIntegral sz)
            bytes <- allocInit ByteStringAllocator sz $ \ fPtr ->
                withPtr fPtr $ \ outPtr ->
                throwBotanIfNegative_ $ botan_pk_op_encrypt
                    encPtr
                    rngPtr
                    outPtr
                    szPtr
                    ptextPtr
                    (fromIntegral ptextLen)
            written <- peek szPtr
            return . MkCiphertext $!! (ByteString.take (fromIntegral written) bytes)

withDecrypt :: Decrypt -> (BotanPKOpDecrypt -> IO a) -> IO a
withDecrypt = withBotanPtr @Decrypt

decryptDestroy :: Decrypt -> IO ()
decryptDestroy = destroyBotan

decryptCreate :: PrivKey -> EME -> IO Decrypt
decryptCreate sk eme = mask_ $
    withPrivKey sk $ \ skPtr ->
    useAsCString (emeName eme) $ \ paddingPtr ->
    createBotan @Decrypt $ \ outPtr -> botan_pk_op_decrypt_create
        outPtr
        skPtr
        paddingPtr
        BOTAN_PUBKEY_DECRYPT_FLAGS_NONE

-- | Upper bound on the output length (in bytes) of decrypting a ciphertext of
-- the given length
decryptGetOutputLength :: Decrypt -> Int -> IO Int
decryptGetOutputLength dec ctextLen = mask_ $
    withDecrypt dec $ \ decPtr ->
    alloca $ \ szPtr -> do
        throwBotanIfNegative_ $
            botan_pk_op_decrypt_output_length decPtr (fromIntegral ctextLen) szPtr
        fromIntegral <$> peek szPtr

decrypt :: Decrypt -> Ciphertext -> IO ByteString
decrypt dec (MkCiphertext ctext) = mask_ $
    withDecrypt dec $ \ decPtr ->
    withPtrLen ctext $ \ ctextPtr ctextLen -> do
        sz <- decryptGetOutputLength dec ctextLen
        alloca $ \ szPtr -> do
            poke szPtr (fromIntegral sz)
            bytes <- allocInit ByteStringAllocator sz $ \ fPtr ->
                withPtr fPtr $ \ outPtr ->
                throwBotanIfNegative_ $ botan_pk_op_decrypt
                    decPtr
                    outPtr
                    szPtr
                    (ConstPtr ctextPtr)
                    (fromIntegral ctextLen)
            written <- peek szPtr
            return $!! ByteString.take (fromIntegral written) bytes
