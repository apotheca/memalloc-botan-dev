module Botan.KDF
(   KDFSecret
,   KDFSalt
,   KDFLabel
,   KDFDerivedKey
,   kdf
,   KDFType(..)
,   kdfName
,   kdfs
) where

import Botan.Internal.Prelude
import Botan.Bindings.KDF
import Botan.Hash
import Botan.MAC

{-
KDF data types
-}

-- | The secret input
type KDFSecret = ByteString

-- | A diversifier
type KDFSalt = ByteString

-- | The purpose for the derived keying material
type KDFLabel = ByteString

-- | The derived keying material
type KDFDerivedKey = ByteString

{-
KDF functions
-}

{- |
Derive keying material of the given length in bytes.

See: <https://botan.randombit.net/doxygen/classBotan_1_1KDF.html>
-}
kdf
    :: KDFType          -- ^ __kdf_algo__: KDF algorithm, e.g., @SP800_56C (HMAC SHA256)@
    -> Int              -- ^ __out_len__: the desired output length in bytes
    -> KDFSecret        -- ^ __secret[]__: the secret input
    -> KDFSalt          -- ^ __salt[]__: a diversifier
    -> KDFLabel         -- ^ __label[]__: purpose for the derived keying material
    -> IO KDFDerivedKey -- ^ __out[]__: the derived key
kdf algo outLen secret salt label = mask_ $
    useAsCString (kdfName algo) $ \ algoPtr ->
    withPtrLen secret $ \ secretPtr secretLen ->
    withPtrLen salt $ \ saltPtr saltLen ->
    withPtrLen label $ \ labelPtr labelLen ->
    allocInit ByteStringAllocator outLen $ \ fPtr -> withPtr fPtr $ \ outPtr ->
        throwBotanIfNegative_ $ botan_kdf
            (ConstPtr algoPtr)
            outPtr
            (fromIntegral outLen)
            (ConstPtr secretPtr)
            (fromIntegral secretLen)
            (ConstPtr saltPtr)
            (fromIntegral saltLen)
            (ConstPtr labelPtr)
            (fromIntegral labelLen)

{-
KDF algorithms
-}

data KDFType
    = HKDF HashType
    | HKDF_Extract HashType
    | HKDF_Expand HashType
    | KDF2 HashType
    | KDF1_18033 HashType
    | KDF1 HashType
    | TLS_12_PRF HashType
    | X9_42_PRF HashType
    | SP800_108_Counter MACType
    | SP800_108_Feedback MACType
    | SP800_108_Pipeline MACType
    | SP800_56A MACType
    | SP800_56C MACType
    deriving stock (Eq, Ord, Show)

kdfName :: KDFType -> ByteString
kdfName (HKDF h)               = BOTAN_KDF_HKDF /$ hashName h
kdfName (HKDF_Extract h)       = BOTAN_KDF_HKDF_EXTRACT /$ hashName h
kdfName (HKDF_Expand h)        = BOTAN_KDF_HKDF_EXPAND /$ hashName h
kdfName (KDF2 h)               = BOTAN_KDF_KDF2 /$ hashName h
kdfName (KDF1_18033 h)         = BOTAN_KDF_KDF1_18033 /$ hashName h
kdfName (KDF1 h)               = BOTAN_KDF_KDF1 /$ hashName h
kdfName (TLS_12_PRF h)         = BOTAN_KDF_TLS_12_PRF /$ hashName h
kdfName (X9_42_PRF h)          = BOTAN_KDF_X9_42_PRF /$ hashName h
kdfName (SP800_108_Counter m)  = BOTAN_KDF_SP800_108_COUNTER /$ macName m
kdfName (SP800_108_Feedback m) = BOTAN_KDF_SP800_108_FEEDBACK /$ macName m
kdfName (SP800_108_Pipeline m) = BOTAN_KDF_SP800_108_PIPELINE /$ macName m
kdfName (SP800_56A m)          = BOTAN_KDF_SP800_56A /$ macName m
kdfName (SP800_56C m)          = BOTAN_KDF_SP800_56C /$ macName m

kdfs :: [KDFType]
kdfs = concat
    [ [ HKDF h | h <- cryptoHashes ]
    , [ HKDF_Extract h | h <- cryptoHashes ]
    , [ HKDF_Expand h | h <- cryptoHashes ]
    , [ KDF2 h | h <- hashes ]
    , [ KDF1_18033 h | h <- hashes ]
    , [ KDF1 h | h <- hashes ]
    , [ TLS_12_PRF h | h <- cryptoHashes ]
    , [ X9_42_PRF SHA1 ]
    , [ SP800_108_Counter (HMAC h) | h <- cryptoHashes ]
    , [ SP800_108_Feedback (HMAC h) | h <- cryptoHashes ]
    , [ SP800_108_Pipeline (HMAC h) | h <- cryptoHashes ]
    , [ SP800_56A (HMAC h) | h <- cryptoHashes ]
    , [ SP800_56C (HMAC h) | h <- cryptoHashes ]
    ]
