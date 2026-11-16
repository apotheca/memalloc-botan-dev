{-# LANGUAGE OverloadedStrings #-}

module Botan.PubKey.Sign
(   pkSign
,   pkVerify
,   Signature(..)
,   SigningFlags(..)
,   EMSA(..)
,   emsaName
,   Sign(..)
,   Verify(..)
,   withSign
,   signCreate
,   signGetOutputLength
,   signUpdate
,   signFinish
,   withVerify
,   verifyCreate
,   verifyUpdate
,   verifyFinish
) where

import Botan.Bindings.PubKey
import Botan.Bindings.PubKey.Sign
import Botan.Bindings.PubKey.Verify

import Botan.Internal.Prelude
import Botan.Hash
import Botan.MPI
import Botan.RNG
import Botan.PubKey

import qualified Data.ByteString as ByteString

-- Main interface
-- TODO: The intermediate IO has been omitted

-- NOTE: IO because RNG
pkSign :: PrivKey -> EMSA -> SigningFlags -> ByteString -> IO Signature
pkSign sk emsa flags msg = do
    s <- signCreate sk emsa flags
    signUpdate s msg
    signFinish s userThreadsafeRNG

pkVerify :: PubKey -> EMSA -> SigningFlags -> ByteString -> Signature -> Bool
pkVerify pk emsa flags msg sig = doIO $ do
    v <- verifyCreate pk emsa flags
    verifyUpdate v msg
    verifyFinish v sig

-- Data types

newtype Signature = MkSignature { signatureBytes :: ByteString }
    deriving newtype (Eq, Show)

data SigningFlags
    = StandardFormatSignature
    | DERFormatSignature
    deriving stock (Show, Eq, Ord, Enum, Bounded)

signingFlags :: SigningFlags -> Word32
signingFlags StandardFormatSignature = BOTAN_PUBKEY_STD_FORMAT_SIGNATURE
signingFlags DERFormatSignature      = BOTAN_PUBKEY_DER_FORMAT_SIGNATURE

-- Algorithm type

-- TODO: Rename PKSigningParams?
data EMSA
    = EMSA_NONE
    -- TODO: | EMSA_RSA / PSS?
    | EMSA4 HashType
    | EMSA_Ed25519Pure
    | EMSA_Ed25519Prehashed
    | EMSA_Ed25519GnuPG HashType
    | EMSA_HASH HashType
    | EMSA_SM2SignParam ByteString HashType
    -- TODO: | EMSA_XMSS
    -- TODO: | EMSA_Dilithium
    deriving stock (Show, Eq, Ord)

-- TODO: Botan should have emsa constants somewhere
emsaName :: EMSA -> ByteString
emsaName EMSA_NONE                 = ""
emsaName (EMSA4 h)                 = "EMSA4" /$ hashName h
emsaName EMSA_Ed25519Pure          = "Pure"
emsaName EMSA_Ed25519Prehashed     = "Ed25519ph"
emsaName (EMSA_Ed25519GnuPG h)     = hashName h
emsaName (EMSA_HASH h)             = hashName h
emsaName (EMSA_SM2SignParam uid h) = commas [ uid, hashName h ]

-- Algorithms

-- Bindings instance

instance Memorized BotanPKOpSign where
    type Memo BotanPKOpSign = Ptr
    type MemRep BotanPKOpSign = BotanPKOpSignStruct
    withMemo (MkBotanPKOpSign ptr) action = action ptr

instance Memorized BotanPKOpVerify where
    type Memo BotanPKOpVerify = Ptr
    type MemRep BotanPKOpVerify = BotanPKOpVerifyStruct
    withMemo (MkBotanPKOpVerify ptr) action = action ptr

-- Context object

-- TODO: Rename PKOpSign
newtype Sign = MkSign { foreignPtr :: ForeignPtr BotanPKOpSignStruct }

instance Memorized Sign where
    type Memo Sign = ForeignPtr
    type MemRep Sign = BotanPKOpSignStruct
    withMemo (MkSign fptr) action = action fptr

instance BotanObject Sign where

    type BotanStruct Sign = BotanPKOpSignStruct
    type BotanPtr    Sign = BotanPKOpSign

    toBotanPtr = MkBotanPKOpSign
    toBotan    = MkSign
    botanFinalizer  = botan_pk_op_sign_destroy

-- TODO: Rename PKOpVerifty
newtype Verify = MkVerify { foreignPtr :: ForeignPtr BotanPKOpVerifyStruct }

instance Memorized Verify where
    type Memo Verify = ForeignPtr
    type MemRep Verify = BotanPKOpVerifyStruct
    withMemo (MkVerify fptr) action = action fptr

instance BotanObject Verify where

    type BotanStruct Verify = BotanPKOpVerifyStruct
    type BotanPtr    Verify = BotanPKOpVerify

    toBotanPtr = MkBotanPKOpVerify
    toBotan    = MkVerify
    botanFinalizer  = botan_pk_op_verify_destroy

-- Bindings / IO interface

withSign :: Sign -> (BotanPKOpSign -> IO a) -> IO a
withSign = withBotanPtr @Sign

signDestroy :: Sign -> IO ()
signDestroy = destroyBotan

signCreate :: PrivKey -> EMSA -> SigningFlags -> IO Sign
signCreate sk emsa flags = mask_ $
    withPrivKey sk $ \ skPtr ->
    useAsCString (emsaName emsa) $ \ algoPtr ->
    createBotan @Sign $ \ outPtr -> botan_pk_op_sign_create
        outPtr
        skPtr
        (ConstPtr algoPtr)
        (signingFlags flags)

-- | Upper bound on the signature length in bytes
signGetOutputLength :: Sign -> IO Int
signGetOutputLength = botanObjectIntegral @_ @CSize botan_pk_op_sign_output_length

signUpdate :: Sign -> ByteString -> IO ()
signUpdate s bs = mask_ $
    withSign s $ \ signPtr ->
    withPtrLen bs $ \ bsPtr bsLen ->
    throwBotanIfNegative_ $
        botan_pk_op_sign_update signPtr (ConstPtr bsPtr) (fromIntegral bsLen)

-- | Finish signing.
--
-- Depending on the algorithm, signatures produced using 'StandardFormatSignature'
-- may have trailing null bytes.
signFinish :: Sign -> RNG -> IO Signature
signFinish s rng = mask_ $
    withSign s $ \ signPtr ->
    withRNG rng $ \ rngPtr -> do
        -- The output length is only an upper bound: poke it, sign, then trim
        -- to the length actually written.
        sz <- signGetOutputLength s
        alloca $ \ szPtr -> do
            poke szPtr (fromIntegral sz)
            bytes <- allocInit ByteStringAllocator sz $ \ fPtr ->
                withPtr fPtr $ \ sigPtr ->
                throwBotanIfNegative_ $
                    botan_pk_op_sign_finish signPtr rngPtr sigPtr szPtr
            written <- peek szPtr
            return . MkSignature $!! ByteString.take (fromIntegral written) bytes

{-
Bindings / IO interface: verification
-}

withVerify :: Verify -> (BotanPKOpVerify -> IO a) -> IO a
withVerify = withBotanPtr @Verify

verifyDestroy :: Verify -> IO ()
verifyDestroy = destroyBotan

verifyCreate :: PubKey -> EMSA -> SigningFlags -> IO Verify
verifyCreate pk emsa flags = mask_ $
    withPubKey pk $ \ pkPtr ->
    useAsCString (emsaName emsa) $ \ algoPtr ->
    createBotan @Verify $ \ outPtr -> botan_pk_op_verify_create
        outPtr
        pkPtr
        (ConstPtr algoPtr)
        (signingFlags flags)

verifyUpdate :: Verify -> ByteString -> IO ()
verifyUpdate v bs = mask_ $
    withVerify v $ \ verifyPtr ->
    withPtrLen bs $ \ bsPtr bsLen ->
    throwBotanIfNegative_ $
        botan_pk_op_verify_update verifyPtr (ConstPtr bsPtr) (fromIntegral bsLen)

-- | Finish verification. Returns False if the signature is invalid.
verifyFinish :: Verify -> Signature -> IO Bool
verifyFinish v (MkSignature sig) = mask_ $
    withVerify v $ \ verifyPtr ->
    withPtrLen sig $ \ sigPtr sigLen ->
    throwBotanCatchingInvalidVerifier $
        botan_pk_op_verify_finish verifyPtr (ConstPtr sigPtr) (fromIntegral sigLen)