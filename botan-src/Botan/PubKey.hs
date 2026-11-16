{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

{-
generatePrivateKey
derivePublicKey
generateKeyPair
encrypt
decrypt
sign
verify
keyAgree
keyEncapsulate
-}

module Botan.PubKey
(
    -- * Private keys
    PrivKey(..)
,   withPrivKey
,   privKeyDestroy
,   privKeyCreate
,   generatePrivKey

,   privKeyLoad
,   privKeyLoadEncrypted
,   privKeyGetAlgoName
,   PKKeyTests(..)
,   privKeyCheckKey
,   PrivKeyExportFlags(..)
,   privKeyExport
,   privKeyExportPubKey
,   privKeyGetField

    -- * Public keys
,   PubKey(..)
,   withPubKey
,   pubKeyDestroy
,   pubKeyLoad
,   PubKeyExportFlags
,   pubKeyExport
,   pubKeyGetAlgoName
,   pubKeyCheckKey
,   pubKeyEstimatedStrength
,   pubKeyFingerprint
,   pubKeyGetField

    -- * Algorithms
,   PKType(..)
,   pkTypeName
,   PKScheme(..)
,   pkSchemeType
,   pkSchemeName
,   pkSchemeParams
,   pkSuggestedScheme

    -- ** Scheme parameters
,   XMSSParams(..)
,   xmssName
,   ECGroup(..)
,   ecGroupName
,   DLGroup(..)
,   dlGroupName
,   KyberMode(..)
,   kyberModeName
,   DilithiumMode(..)
,   dilithiumModeName
,   ClassicMcElieceParams(..)
,   classicMcElieceParamsName
,   FrodoKEMMode(..)
,   frodoKEMModeName
,   SphincsPlusMode(..)
,   sphincsPlusModeName
,   SLH_DSAMode(..)
,   slh_dsaModeName

    -- * Helpers
-- ,   mkPrivKeyLoad1_name
-- ,   mkPrivKeyLoad3
-- ,   mkPrivKeyLoad4
-- ,   mkPubKeyLoad2
-- ,   mkPubKeyLoad2_name
-- ,   mkPubKeyLoad3
-- ,   mkPubKeyLoad4
) where

import Botan.Bindings.PubKey
import Botan.Bindings.PubKey.Decrypt
import Botan.Bindings.PubKey.Encrypt
import Botan.Bindings.PubKey.Sign
import Botan.Bindings.PubKey.Verify
import Botan.Bindings.RNG
import Botan.Hash (HashType, hashName)
import Botan.Internal.Prelude
import Botan.MPI
import Botan.RNG

import qualified Data.ByteString as ByteString
import qualified Foreign.Ptr as Foreign
import Foreign.Marshal.Utils (withMany)

{-
Bindings Memorized instances
-}

instance Memorized BotanPrivKey where
    type Memo BotanPrivKey = Ptr
    type MemRep BotanPrivKey = BotanPrivKeyStruct
    withMemo (MkBotanPrivKey ptr) action = action ptr

instance Memorized BotanPubKey where
    type Memo BotanPubKey = Ptr
    type MemRep BotanPubKey = BotanPubKeyStruct
    withMemo (MkBotanPubKey ptr) action = action ptr

{-
PrivKey object
-}

newtype PrivKey = MkPrivKey { foreignPtr :: ForeignPtr BotanPrivKeyStruct }

instance Memorized PrivKey where
    type Memo PrivKey = ForeignPtr
    type MemRep PrivKey = BotanPrivKeyStruct
    withMemo (MkPrivKey fptr) action = action fptr

instance BotanObject PrivKey where

    type BotanStruct PrivKey = BotanPrivKeyStruct
    type BotanPtr    PrivKey = BotanPrivKey

    toBotanPtr = MkBotanPrivKey
    toBotan    = MkPrivKey
    botanFinalizer  = botan_privkey_destroy

withPrivKey :: PrivKey -> (BotanPrivKey -> IO a) -> IO a
withPrivKey = withBotanPtr

privKeyDestroy :: PrivKey -> IO ()
privKeyDestroy = destroyBotan

{-
PubKey object
-}

newtype PubKey = MkPubKey { foreignPtr :: ForeignPtr BotanPubKeyStruct }

instance Memorized PubKey where
    type Memo PubKey = ForeignPtr
    type MemRep PubKey = BotanPubKeyStruct
    withMemo (MkPubKey fptr) action = action fptr

instance BotanObject PubKey where

    type BotanStruct PubKey = BotanPubKeyStruct
    type BotanPtr    PubKey = BotanPubKey

    toBotanPtr = MkBotanPubKey
    toBotan    = MkPubKey
    botanFinalizer  = botan_pubkey_destroy

withPubKey :: PubKey -> (BotanPubKey -> IO a) -> IO a
withPubKey = withBotanPtr

pubKeyDestroy :: PubKey -> IO ()
pubKeyDestroy = destroyBotan

{-
PrivKey functions
-}

-- | Create a new private key
privKeyCreate :: PKScheme -> RNG -> IO PrivKey
privKeyCreate scheme rng =
    useAsCString (pkSchemeName scheme) $ \ namePtr ->
    useAsCString (pkSchemeParams scheme) $ \ paramsPtr ->
    withRNG rng $ \ botanRNG ->
    createBotan @PrivKey $ \ outPtr -> botan_privkey_create
        outPtr
        (ConstPtr namePtr)
        (ConstPtr paramsPtr)
        botanRNG

-- | Create a new private key using the global user threadsafe RNG
generatePrivKey :: PKScheme -> IO PrivKey
generatePrivKey scheme = privKeyCreate scheme userThreadsafeRNG

-- TODO: GenerateKeyPair

-- | Load an unencrypted private key (PKCS #8, DER or PEM)
privKeyLoad :: ByteString -> IO PrivKey
privKeyLoad bits = mask_ $
    withPtrLen bits $ \ bitsPtr bitsLen ->
    createBotan @PrivKey $ \ outPtr -> botan_privkey_load
        outPtr
        (MkBotanRNG Foreign.nullPtr)   -- NOTE: rng is unused since Botan 2.8.0
        (ConstPtr bitsPtr)
        (fromIntegral bitsLen)
        (ConstPtr Foreign.nullPtr)

-- | Load an encrypted private key (PKCS #8, DER or PEM) using a password
privKeyLoadEncrypted
    :: ByteString   -- ^ __bits__
    -> ByteString   -- ^ __password__
    -> IO PrivKey
privKeyLoadEncrypted bits password = mask_ $
    withPtrLen bits $ \ bitsPtr bitsLen ->
    useAsCString password $ \ passwordPtr ->
    createBotan @PrivKey $ \ outPtr -> botan_privkey_load
        outPtr
        (MkBotanRNG Foreign.nullPtr)
        (ConstPtr bitsPtr)
        (fromIntegral bitsLen)
        (ConstPtr passwordPtr)

privKeyGetAlgoName :: PrivKey -> IO ByteString
privKeyGetAlgoName = botanObjectName botan_privkey_algo_name

data PKKeyTests
    = PKNormalTests
    | PKExpensiveTests
    deriving stock (Show, Eq, Ord)

pkKeyTestFlags :: PKKeyTests -> Word32
pkKeyTestFlags PKNormalTests    = BOTAN_CHECK_KEY_NORMAL_TESTS
pkKeyTestFlags PKExpensiveTests = BOTAN_CHECK_KEY_EXPENSIVE_TESTS

-- | Check the validity of a private key. Returns False if the key is invalid.
privKeyCheckKey :: PrivKey -> RNG -> PKKeyTests -> IO Bool
privKeyCheckKey sk rng tests = mask_ $
    withPrivKey sk $ \ skPtr ->
    withRNG rng $ \ rngPtr ->
    throwBotanCatchingInvalidInput $
        botan_privkey_check_key skPtr rngPtr (pkKeyTestFlags tests)

data PrivKeyExportFlags
    = PrivKeyExportDER
    | PrivKeyExportPEM
    deriving stock (Show, Eq, Ord)

privKeyExportFlags :: PrivKeyExportFlags -> Word32
privKeyExportFlags PrivKeyExportDER = BOTAN_PRIVKEY_EXPORT_FLAG_DER
privKeyExportFlags PrivKeyExportPEM = BOTAN_PRIVKEY_EXPORT_FLAG_PEM

-- | Export a private key (unencrypted) as PKCS #8
privKeyExport :: PrivKey -> PrivKeyExportFlags -> IO ByteString
privKeyExport sk flags = mask_ $ withPrivKey sk $ \ skPtr -> do
    bytes <- allocQueried $ \ outPtr szPtr ->
        botan_privkey_export skPtr outPtr szPtr (privKeyExportFlags flags)
    return $ case flags of
        PrivKeyExportDER -> bytes
        PrivKeyExportPEM -> ByteString.takeWhile (/= 0) bytes

privKeyExportPubKey :: PrivKey -> IO PubKey
privKeyExportPubKey sk = mask_ $ withPrivKey sk $ \ skPtr ->
    createBotan @PubKey $ \ outPtr -> botan_privkey_export_pubkey outPtr skPtr

-- | Get an arbitrary named field (eg "n", "e", "d" for RSA) as an 'Integer'
privKeyGetField :: PrivKey -> ByteString -> IO Integer
privKeyGetField sk field = mask_ $ do
    mp <- mpInit
    withMP mp $ \ mpPtr ->
        withPrivKey sk $ \ skPtr ->
        useAsCString field $ \ fieldPtr ->
        throwBotanIfNegative_ $ botan_privkey_get_field
            mpPtr
            skPtr
            (ConstPtr fieldPtr)
    mpToInteger mp

{-
PubKey functions
-}

pubKeyLoad :: ByteString -> IO PubKey
pubKeyLoad bits = mask_ $
    withPtrLen bits $ \ bitsPtr bitsLen ->
    createBotan @PubKey $ \ outPtr -> botan_pubkey_load
        outPtr
        (ConstPtr bitsPtr)
        (fromIntegral bitsLen)

type PubKeyExportFlags = PrivKeyExportFlags

pubKeyExport :: PubKey -> PubKeyExportFlags -> IO ByteString
pubKeyExport pk flags = mask_ $ withPubKey pk $ \ pkPtr -> do
    bytes <- allocQueried $ \ outPtr szPtr ->
        botan_pubkey_export pkPtr outPtr szPtr (privKeyExportFlags flags)
    return $ case flags of
        PrivKeyExportDER -> bytes
        PrivKeyExportPEM -> ByteString.takeWhile (/= 0) bytes

pubKeyGetAlgoName :: PubKey -> IO ByteString
pubKeyGetAlgoName = botanObjectName botan_pubkey_algo_name

-- | Check the validity of a public key. Returns False if the key is invalid.
pubKeyCheckKey :: PubKey -> RNG -> PKKeyTests -> IO Bool
pubKeyCheckKey pk rng tests = mask_ $
    withPubKey pk $ \ pkPtr ->
    withRNG rng $ \ rngPtr ->
    throwBotanCatchingInvalidInput $
        botan_pubkey_check_key pkPtr rngPtr (pkKeyTestFlags tests)

pubKeyEstimatedStrength :: PubKey -> IO Int
pubKeyEstimatedStrength = botanObjectIntegral botan_pubkey_estimated_strength

pubKeyFingerprint :: PubKey -> HashType -> IO ByteString
pubKeyFingerprint pk h = mask_ $
    withPubKey pk $ \ pkPtr ->
    useAsCString (hashName h) $ \ hashPtr ->
    allocQueried $ \ outPtr szPtr ->
        botan_pubkey_fingerprint pkPtr (ConstPtr hashPtr) outPtr szPtr

-- | Get an arbitrary named field as an 'Integer'
pubKeyGetField :: PubKey -> ByteString -> IO Integer
pubKeyGetField pk field = mask_ $ do
    mp <- mpInit
    withMP mp $ \ mpPtr ->
        withPubKey pk $ \ pkPtr ->
        useAsCString field $ \ fieldPtr ->
        throwBotanIfNegative_ $ botan_pubkey_get_field
            mpPtr
            pkPtr
            (ConstPtr fieldPtr)
    mpToInteger mp

{-
Public key types
-}

-- NOTE: Not every type is supported by every botan build; see the (forthcoming)
-- pkTypeIsSupported.
data PKType
    = RSAType
    | SM2Type
    | ElGamalType
    | DSAType
    | ECDSAType
    | ECKCDSAType
    | ECGDSAType
    | GOST_34_10Type
    | Ed25519Type
    | Ed448Type
    | XMSSType
    | DHType
    | ECDHType
    | X25519Type
    | X448Type
    | DilithiumType
    | ML_DSAType
    | KyberType
    | ML_KEMType
    | McElieceType
    | ClassicMcElieceType
    | FrodoKEMType
    | HSS_LMSType
    | SphincsPlusType
    | SLH_DSAType
    deriving stock (Show, Eq, Ord, Enum, Bounded)

pkTypeName :: PKType -> ByteString
pkTypeName RSAType             = BOTAN_PK_RSA
pkTypeName SM2Type             = BOTAN_PK_SM2
pkTypeName ElGamalType         = BOTAN_PK_ELGAMAL
pkTypeName DSAType             = BOTAN_PK_DSA
pkTypeName ECDSAType           = BOTAN_PK_ECDSA
pkTypeName ECKCDSAType         = BOTAN_PK_ECKCDSA
pkTypeName ECGDSAType          = BOTAN_PK_ECGDSA
pkTypeName GOST_34_10Type      = BOTAN_PK_GOST_34_10
pkTypeName Ed25519Type         = BOTAN_PK_ED25519
pkTypeName Ed448Type           = "Ed448"
pkTypeName XMSSType            = BOTAN_PK_XMSS
pkTypeName DHType              = BOTAN_PK_DH
pkTypeName ECDHType            = BOTAN_PK_ECDH
pkTypeName X25519Type          = BOTAN_PK_CURVE25519
pkTypeName X448Type            = "X448"
pkTypeName DilithiumType       = BOTAN_PK_DILITHIUM
pkTypeName ML_DSAType          = "ML-DSA"
pkTypeName KyberType           = BOTAN_PK_KYBER
pkTypeName ML_KEMType          = "ML-KEM"
pkTypeName McElieceType        = BOTAN_PK_MCELIECE
pkTypeName ClassicMcElieceType = "ClassicMcEliece"
pkTypeName FrodoKEMType        = "FrodoKEM"
pkTypeName HSS_LMSType         = "HSS-LMS"
pkTypeName SphincsPlusType     = "SPHINCS+"
pkTypeName SLH_DSAType         = "SLH-DSA"

data PKScheme
    = RSA Word32
    | SM2 ECGroup
    | ElGamal DLGroup
    | DSA DLGroup
    | ECDSA ECGroup
    | ECKCDSA ECGroup
    | ECGDSA ECGroup
    | GOST_34_10 ECGroup -- gost_256A or gost_512A
    | Ed25519
    | Ed448
    | XMSS XMSSParams
    | DH DLGroup
    | ECDH ECGroup
    | X25519
    | X448
    | Dilithium DilithiumMode
    | ML_DSA DilithiumMode
    | Kyber KyberMode
    | ML_KEM KyberMode
    | McEliece Word32 Word32 -- n, t -- TODO: Make a McEliece parameter type
    | ClassicMcEliece ClassicMcElieceParams
    | FrodoKEM FrodoKEMMode
    | HSS_LMS ByteString -- TODO: Make a HSS-LMS parameter type
    | SphincsPlus SphincsPlusMode
    | SLH_DSA SLH_DSAMode
    deriving stock (Show, Eq)

pkSchemeType :: PKScheme -> PKType
pkSchemeType (RSA _)              = RSAType
pkSchemeType (SM2 _)              = SM2Type
pkSchemeType (ElGamal _)          = ElGamalType
pkSchemeType (DSA _)              = DSAType
pkSchemeType (ECDSA _)            = ECDSAType
pkSchemeType (ECKCDSA _)          = ECKCDSAType
pkSchemeType (ECGDSA _)           = ECGDSAType
pkSchemeType (GOST_34_10 _)       = GOST_34_10Type
pkSchemeType Ed25519              = Ed25519Type
pkSchemeType Ed448                = Ed448Type
pkSchemeType (XMSS _)             = XMSSType
pkSchemeType (DH _)               = DHType
pkSchemeType (ECDH _)             = ECDHType
pkSchemeType X25519               = X25519Type
pkSchemeType X448                 = X448Type
pkSchemeType (Dilithium _)        = DilithiumType
pkSchemeType (ML_DSA _)           = ML_DSAType
pkSchemeType (Kyber _)            = KyberType
pkSchemeType (ML_KEM _)           = ML_KEMType
pkSchemeType (McEliece _ _)       = McElieceType
pkSchemeType (ClassicMcEliece _)  = ClassicMcElieceType
pkSchemeType (FrodoKEM _)         = FrodoKEMType
pkSchemeType (HSS_LMS _)          = HSS_LMSType
pkSchemeType (SphincsPlus _)      = SphincsPlusType
pkSchemeType (SLH_DSA _)          = SLH_DSAType

pkSchemeName :: PKScheme -> ByteString
pkSchemeName = pkTypeName . pkSchemeType

pkSchemeParams :: PKScheme -> ByteString
pkSchemeParams (RSA bits)              = prn bits
pkSchemeParams (SM2 grp)               = ecGroupName grp
pkSchemeParams (ElGamal grp)           = dlGroupName grp
pkSchemeParams (DSA grp)               = dlGroupName grp
pkSchemeParams (ECDSA grp)             = ecGroupName grp
pkSchemeParams (ECKCDSA grp)           = ecGroupName grp
pkSchemeParams (ECGDSA grp)            = ecGroupName grp
pkSchemeParams (GOST_34_10 grp)        = ecGroupName grp
pkSchemeParams Ed25519                 = ""
pkSchemeParams Ed448                   = ""
pkSchemeParams (XMSS xmss)             = xmssName xmss
pkSchemeParams (DH grp)                = dlGroupName grp
pkSchemeParams (ECDH grp)              = ecGroupName grp
pkSchemeParams X25519                  = ""
pkSchemeParams X448                    = ""
pkSchemeParams (Dilithium mode)        = dilithiumModeName mode
pkSchemeParams (ML_DSA mode)           = dilithiumModeName mode
pkSchemeParams (Kyber mode)            = kyberModeName mode
pkSchemeParams (ML_KEM mode)           = kyberModeName mode
pkSchemeParams (McEliece n t)          = prn n <> "," <> prn t
pkSchemeParams (ClassicMcEliece p)     = classicMcElieceParamsName p
pkSchemeParams (FrodoKEM mode)         = frodoKEMModeName mode
pkSchemeParams (HSS_LMS params)        = params
pkSchemeParams (SphincsPlus mode)      = sphincsPlusModeName mode
pkSchemeParams (SLH_DSA mode)          = slh_dsaModeName mode

pkSuggestedScheme :: PKType -> PKScheme
pkSuggestedScheme RSAType             = RSA 3072
pkSuggestedScheme SM2Type             = SM2 Sm2p256v1
pkSuggestedScheme ElGamalType         = ElGamal MODP_IETF_2048
pkSuggestedScheme DSAType             = DSA DSA_BOTAN_2048
pkSuggestedScheme ECDSAType           = ECDSA Secp256r1
pkSuggestedScheme ECKCDSAType         = ECKCDSA Secp256r1
pkSuggestedScheme ECGDSAType          = ECGDSA Brainpool256r1
pkSuggestedScheme GOST_34_10Type      = GOST_34_10 Gost_256A
pkSuggestedScheme Ed25519Type         = Ed25519
pkSuggestedScheme Ed448Type           = Ed448
pkSuggestedScheme XMSSType            = XMSS XMSS_SHA2_10_512
pkSuggestedScheme DHType              = DH MODP_IETF_2048
pkSuggestedScheme ECDHType            = ECDH Secp256r1
pkSuggestedScheme X25519Type          = X25519
pkSuggestedScheme X448Type            = X448
pkSuggestedScheme DilithiumType       = Dilithium Dilithium6x5
pkSuggestedScheme ML_DSAType          = ML_DSA ML_DSA_6x5
pkSuggestedScheme KyberType           = Kyber Kyber1024_R3
pkSuggestedScheme ML_KEMType          = ML_KEM ML_KEM_768
pkSuggestedScheme McElieceType        = McEliece 2960 57
pkSuggestedScheme ClassicMcElieceType = ClassicMcEliece ClassicMcEliece_6960119f
pkSuggestedScheme FrodoKEMType        = FrodoKEM FrodoKEM976_SHAKE
pkSuggestedScheme HSS_LMSType         = HSS_LMS "SHA-256,HW(10,1)"
pkSuggestedScheme SphincsPlusType     = SphincsPlus SphincsPlus_SHA2_128_Small
pkSuggestedScheme SLH_DSAType         = SLH_DSA SLH_DSA_SHA2_128_Small

-- TODO: pkTypeIsSupported (requires updated FFI bindings for the BOTAN_HAS_*
-- constants; see PubKeySchemes.hs for the draft)

{-
Scheme parameter types
-}

data XMSSParams
    = XMSS_SHA2_10_256
    | XMSS_SHA2_16_256
    | XMSS_SHA2_20_256
    | XMSS_SHA2_10_512
    | XMSS_SHA2_16_512
    | XMSS_SHA2_20_512
    | XMSS_SHAKE_10_256
    | XMSS_SHAKE_16_256
    | XMSS_SHAKE_20_256
    | XMSS_SHAKE_10_512
    | XMSS_SHAKE_16_512
    | XMSS_SHAKE_20_512
    | XMSS_SHA2_10_192
    | XMSS_SHA2_16_192
    | XMSS_SHA2_20_192
    | XMSS_SHAKE256_10_256
    | XMSS_SHAKE256_16_256
    | XMSS_SHAKE256_20_256
    | XMSS_SHAKE256_10_192
    | XMSS_SHAKE256_16_192
    | XMSS_SHAKE256_20_192
    deriving stock (Show, Eq, Ord, Enum, Bounded)

xmssName :: XMSSParams -> ByteString
xmssName XMSS_SHA2_10_256     = BOTAN_XMSS_SHA2_10_256
xmssName XMSS_SHA2_16_256     = BOTAN_XMSS_SHA2_16_256
xmssName XMSS_SHA2_20_256     = BOTAN_XMSS_SHA2_20_256
xmssName XMSS_SHA2_10_512     = BOTAN_XMSS_SHA2_10_512
xmssName XMSS_SHA2_16_512     = BOTAN_XMSS_SHA2_16_512
xmssName XMSS_SHA2_20_512     = BOTAN_XMSS_SHA2_20_512
xmssName XMSS_SHAKE_10_256    = BOTAN_XMSS_SHAKE_10_256
xmssName XMSS_SHAKE_16_256    = BOTAN_XMSS_SHAKE_16_256
xmssName XMSS_SHAKE_20_256    = BOTAN_XMSS_SHAKE_20_256
xmssName XMSS_SHAKE_10_512    = BOTAN_XMSS_SHAKE_10_512
xmssName XMSS_SHAKE_16_512    = BOTAN_XMSS_SHAKE_16_512
xmssName XMSS_SHAKE_20_512    = BOTAN_XMSS_SHAKE_20_512
xmssName XMSS_SHA2_10_192     = "XMSS-SHA2_10_192"
xmssName XMSS_SHA2_16_192     = "XMSS-SHA2_16_192"
xmssName XMSS_SHA2_20_192     = "XMSS-SHA2_20_192"
xmssName XMSS_SHAKE256_10_256 = "XMSS-SHAKE256_10_256"
xmssName XMSS_SHAKE256_16_256 = "XMSS-SHAKE256_16_256"
xmssName XMSS_SHAKE256_20_256 = "XMSS-SHAKE256_20_256"
xmssName XMSS_SHAKE256_10_192 = "XMSS-SHAKE256_10_192"
xmssName XMSS_SHAKE256_16_192 = "XMSS-SHAKE256_16_192"
xmssName XMSS_SHAKE256_20_192 = "XMSS-SHAKE256_20_192"

data ECGroup
    = Secp160k1
    | Secp160r1
    | Secp160r2
    | Secp192k1
    | Secp192r1
    | Secp224k1
    | Secp224r1
    | Secp256k1
    | Secp256r1
    | Secp384r1
    | Secp521r1
    | Brainpool160r1
    | Brainpool192r1
    | Brainpool224r1
    | Brainpool256r1
    | Brainpool320r1
    | Brainpool384r1
    | Brainpool512r1
    | X962_p192v2
    | X962_p192v3
    | X962_p239v1
    | X962_p239v2
    | X962_p239v3
    | Gost_256A
    | Gost_512A
    | Frp256v1
    | Sm2p256v1
    deriving stock (Show, Eq, Ord, Enum, Bounded)

ecGroupName :: ECGroup -> ByteString
ecGroupName Secp160k1       = BOTAN_ECGROUP_SECP_160_K1
ecGroupName Secp160r1       = BOTAN_ECGROUP_SECP_160_R1
ecGroupName Secp160r2       = BOTAN_ECGROUP_SECP_160_R2
ecGroupName Secp192k1       = BOTAN_ECGROUP_SECP_192_K1
ecGroupName Secp192r1       = BOTAN_ECGROUP_SECP_192_R1
ecGroupName Secp224k1       = BOTAN_ECGROUP_SECP_224_K1
ecGroupName Secp224r1       = BOTAN_ECGROUP_SECP_224_R1
ecGroupName Secp256k1       = BOTAN_ECGROUP_SECP_256_K1
ecGroupName Secp256r1       = BOTAN_ECGROUP_SECP_256_R1
ecGroupName Secp384r1       = BOTAN_ECGROUP_SECP_384_R1
ecGroupName Secp521r1       = BOTAN_ECGROUP_SECP_521_R1
ecGroupName Brainpool160r1  = BOTAN_ECGROUP_BRAINPOOL_160_R1
ecGroupName Brainpool192r1  = BOTAN_ECGROUP_BRAINPOOL_192_R1
ecGroupName Brainpool224r1  = BOTAN_ECGROUP_BRAINPOOL_224_R1
ecGroupName Brainpool256r1  = BOTAN_ECGROUP_BRAINPOOL_256_R1
ecGroupName Brainpool320r1  = BOTAN_ECGROUP_BRAINPOOL_320_R1
ecGroupName Brainpool384r1  = BOTAN_ECGROUP_BRAINPOOL_384_R1
ecGroupName Brainpool512r1  = BOTAN_ECGROUP_BRAINPOOL_512_R1
ecGroupName X962_p192v2     = BOTAN_ECGROUP_X962_P192_V2
ecGroupName X962_p192v3     = BOTAN_ECGROUP_X962_P192_V3
ecGroupName X962_p239v1     = BOTAN_ECGROUP_X962_P239_V1
ecGroupName X962_p239v2     = BOTAN_ECGROUP_X962_P239_V2
ecGroupName X962_p239v3     = BOTAN_ECGROUP_X962_P239_V3
ecGroupName Gost_256A       = BOTAN_ECGROUP_GOST_256A
ecGroupName Gost_512A       = BOTAN_ECGROUP_GOST_512A
ecGroupName Frp256v1        = BOTAN_ECGROUP_FRP_256_V1
ecGroupName Sm2p256v1       = BOTAN_ECGROUP_SM2_P256_V1

data DLGroup
    = FFDHE_IETF_2048
    | FFDHE_IETF_3072
    | FFDHE_IETF_4096
    | FFDHE_IETF_6144
    | FFDHE_IETF_8192
    | MODP_IETF_1024
    | MODP_IETF_1536
    | MODP_IETF_2048
    | MODP_IETF_3072
    | MODP_IETF_4096
    | MODP_IETF_6144
    | MODP_IETF_8192
    | MODP_SRP_1024
    | MODP_SRP_1536
    | MODP_SRP_2048
    | MODP_SRP_3072
    | MODP_SRP_4096
    | MODP_SRP_6144
    | MODP_SRP_8192
    | DSA_JCE_1024
    | DSA_BOTAN_2048
    | DSA_BOTAN_3072
    deriving stock (Show, Eq, Ord, Enum, Bounded)

dlGroupName :: DLGroup -> ByteString
dlGroupName FFDHE_IETF_2048 = BOTAN_DLGROUP_FFDHE_IETF_2048
dlGroupName FFDHE_IETF_3072 = BOTAN_DLGROUP_FFDHE_IETF_3072
dlGroupName FFDHE_IETF_4096 = BOTAN_DLGROUP_FFDHE_IETF_4096
dlGroupName FFDHE_IETF_6144 = BOTAN_DLGROUP_FFDHE_IETF_6144
dlGroupName FFDHE_IETF_8192 = BOTAN_DLGROUP_FFDHE_IETF_8192
dlGroupName MODP_IETF_1024  = BOTAN_DLGROUP_MODP_IETF_1024
dlGroupName MODP_IETF_1536  = BOTAN_DLGROUP_MODP_IETF_1536
dlGroupName MODP_IETF_2048  = BOTAN_DLGROUP_MODP_IETF_2048
dlGroupName MODP_IETF_3072  = BOTAN_DLGROUP_MODP_IETF_3072
dlGroupName MODP_IETF_4096  = BOTAN_DLGROUP_MODP_IETF_4096
dlGroupName MODP_IETF_6144  = BOTAN_DLGROUP_MODP_IETF_6144
dlGroupName MODP_IETF_8192  = BOTAN_DLGROUP_MODP_IETF_8192
dlGroupName MODP_SRP_1024   = BOTAN_DLGROUP_MODP_SRP_1024
dlGroupName MODP_SRP_1536   = BOTAN_DLGROUP_MODP_SRP_1536
dlGroupName MODP_SRP_2048   = BOTAN_DLGROUP_MODP_SRP_2048
dlGroupName MODP_SRP_3072   = BOTAN_DLGROUP_MODP_SRP_3072
dlGroupName MODP_SRP_4096   = BOTAN_DLGROUP_MODP_SRP_4096
dlGroupName MODP_SRP_6144   = BOTAN_DLGROUP_MODP_SRP_6144
dlGroupName MODP_SRP_8192   = BOTAN_DLGROUP_MODP_SRP_8192
dlGroupName DSA_JCE_1024    = BOTAN_DLGROUP_DSA_JCE_1024
dlGroupName DSA_BOTAN_2048  = BOTAN_DLGROUP_DSA_BOTAN_2048
dlGroupName DSA_BOTAN_3072  = BOTAN_DLGROUP_DSA_BOTAN_3072

data KyberMode
    = Kyber512_R3   -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    | Kyber768_R3   -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    | Kyber1024_R3  -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    | ML_KEM_512
    | ML_KEM_768
    | ML_KEM_1024
    | Kyber512_90s  -- Deprecated: Kyber 90s mode
    | Kyber768_90s  -- Deprecated: Kyber 90s mode
    | Kyber1024_90s -- Deprecated: Kyber 90s mode
    deriving stock (Show, Eq, Ord, Enum, Bounded)

kyberModeName :: KyberMode -> ByteString
kyberModeName Kyber512_R3   = "Kyber-512-r3"
kyberModeName Kyber768_R3   = "Kyber-768-r3"
kyberModeName Kyber1024_R3  = "Kyber-1024-r3"
kyberModeName ML_KEM_512    = "ML-KEM-512"
kyberModeName ML_KEM_768    = "ML-KEM-768"
kyberModeName ML_KEM_1024   = "ML-KEM-1024"
kyberModeName Kyber512_90s  = "Kyber-512-90s"
kyberModeName Kyber768_90s  = "Kyber-768-90s"
kyberModeName Kyber1024_90s = "Kyber-1024-90s"

data DilithiumMode
    = Dilithium4x4     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium6x5     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium8x7     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium4x4_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium6x5_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium8x7_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | ML_DSA_4x4
    | ML_DSA_6x5
    | ML_DSA_8x7
    deriving stock (Show, Eq, Ord, Enum, Bounded)

dilithiumModeName :: DilithiumMode -> ByteString
dilithiumModeName Dilithium4x4     = "Dilithium-4x4-r3"
dilithiumModeName Dilithium6x5     = "Dilithium-6x5-r3"
dilithiumModeName Dilithium8x7     = "Dilithium-8x7-r3"
dilithiumModeName Dilithium4x4_AES = "Dilithium-4x4-AES-r3"
dilithiumModeName Dilithium6x5_AES = "Dilithium-6x5-AES-r3"
dilithiumModeName Dilithium8x7_AES = "Dilithium-8x7-AES-r3"
dilithiumModeName ML_DSA_4x4       = "ML-DSA-4x4"
dilithiumModeName ML_DSA_6x5       = "ML-DSA-6x5"
dilithiumModeName ML_DSA_8x7       = "ML-DSA-8x7"

data ClassicMcElieceParams
    = ClassicMcEliece_348864      -- NIST
    | ClassicMcEliece_348864f     -- NIST
    | ClassicMcEliece_460896      -- NIST
    | ClassicMcEliece_460896f     -- NIST
    | ClassicMcEliece_6688128     -- ISO + NIST
    | ClassicMcEliece_6688128f    -- ISO + NIST
    | ClassicMcEliece_6688128pc   -- ISO
    | ClassicMcEliece_6688128pcf  -- ISO
    | ClassicMcEliece_6960119     -- ISO + NIST
    | ClassicMcEliece_6960119f    -- ISO + NIST
    | ClassicMcEliece_6960119pc   -- ISO
    | ClassicMcEliece_6960119pcf  -- ISO
    | ClassicMcEliece_8192128     -- ISO + NIST
    | ClassicMcEliece_8192128f    -- ISO + NIST
   | ClassicMcEliece_8192128pc   -- ISO
    | ClassicMcEliece_8192128pcf  -- ISO
    deriving stock (Show, Eq, Ord, Enum, Bounded)

classicMcElieceParamsName :: ClassicMcElieceParams -> ByteString
classicMcElieceParamsName ClassicMcEliece_348864     = "ClassicMcEliece_348864"
classicMcElieceParamsName ClassicMcEliece_348864f    = "ClassicMcEliece_348864f"
classicMcElieceParamsName ClassicMcEliece_460896     = "ClassicMcEliece_460896"
classicMcElieceParamsName ClassicMcEliece_460896f    = "ClassicMcEliece_460896f"
classicMcElieceParamsName ClassicMcEliece_6688128    = "ClassicMcEliece_6688128"
classicMcElieceParamsName ClassicMcEliece_6688128f   = "ClassicMcEliece_6688128f"
classicMcElieceParamsName ClassicMcEliece_6688128pc  = "ClassicMcEliece_6688128pc"
classicMcElieceParamsName ClassicMcEliece_6688128pcf = "ClassicMcEliece_6688128pcf"
classicMcElieceParamsName ClassicMcEliece_6960119    = "ClassicMcEliece_6960119"
classicMcElieceParamsName ClassicMcEliece_6960119f   = "ClassicMcEliece_6960119f"
classicMcElieceParamsName ClassicMcEliece_6960119pc  = "ClassicMcEliece_6960119pc"
classicMcElieceParamsName ClassicMcEliece_6960119pcf = "ClassicMcEliece_6960119pcf"
classicMcElieceParamsName ClassicMcEliece_8192128    = "ClassicMcEliece_8192128"
classicMcElieceParamsName ClassicMcEliece_8192128f   = "ClassicMcEliece_8192128f"
classicMcElieceParamsName ClassicMcEliece_8192128pc  = "ClassicMcEliece_8192128pc"
classicMcElieceParamsName ClassicMcEliece_8192128pcf = "ClassicMcEliece_8192128pcf"

-- NOTE: Strings are formatted as `(e)FrodoKEM-<size>-<mode>`
data FrodoKEMMode
    = FrodoKEM640_SHAKE
    | FrodoKEM976_SHAKE
    | FrodoKEM1344_SHAKE
    | EphemeralFrodoKEM640_SHAKE
    | EphemeralFrodoKEM976_SHAKE
    | EphemeralFrodoKEM1344_SHAKE
    | FrodoKEM640_AES
    | FrodoKEM976_AES
    | FrodoKEM1344_AES
    | EphemeralFrodoKEM640_AES
    | EphemeralFrodoKEM976_AES
    | EphemeralFrodoKEM1344_AES
    deriving stock (Show, Eq, Ord, Enum, Bounded)

frodoKEMModeName :: FrodoKEMMode -> ByteString
frodoKEMModeName FrodoKEM640_SHAKE            = "FrodoKEM-640-SHAKE"
frodoKEMModeName FrodoKEM976_SHAKE            = "FrodoKEM-976-SHAKE"
frodoKEMModeName FrodoKEM1344_SHAKE           = "FrodoKEM-1344-SHAKE"
frodoKEMModeName EphemeralFrodoKEM640_SHAKE   = "eFrodoKEM-640-SHAKE"
frodoKEMModeName EphemeralFrodoKEM976_SHAKE   = "eFrodoKEM-976-SHAKE"
frodoKEMModeName EphemeralFrodoKEM1344_SHAKE  = "eFrodoKEM-1344-SHAKE"
frodoKEMModeName FrodoKEM640_AES              = "FrodoKEM-640-AES"
frodoKEMModeName FrodoKEM976_AES              = "FrodoKEM-976-AES"
frodoKEMModeName FrodoKEM1344_AES             = "FrodoKEM-1344-AES"
frodoKEMModeName EphemeralFrodoKEM640_AES     = "eFrodoKEM-640-AES"
frodoKEMModeName EphemeralFrodoKEM976_AES     = "eFrodoKEM-976-AES"
frodoKEMModeName EphemeralFrodoKEM1344_AES    = "eFrodoKEM-1344-AES"

-- NOTE: Deprecated in favor of SLH-DSA. Could break into Hash, Parameter set,
-- but an enum is fine
data SphincsPlusMode
    = SphincsPlus_SHA2_128_Small
    | SphincsPlus_SHA2_128_Fast
    | SphincsPlus_SHA2_192_Small
    | SphincsPlus_SHA2_192_Fast
    | SphincsPlus_SHA2_256_Small
    | SphincsPlus_SHA2_256_Fast
    | SphincsPlus_SHAKE_128_Small
    | SphincsPlus_SHAKE_128_Fast
    | SphincsPlus_SHAKE_192_Small
    | SphincsPlus_SHAKE_192_Fast
    | SphincsPlus_SHAKE_256_Small
    | SphincsPlus_SHAKE_256_Fast
    | SphincsPlus_Haraka_128_Small
    | SphincsPlus_Haraka_128_Fast
    | SphincsPlus_Haraka_192_Small
    | SphincsPlus_Haraka_192_Fast
    | SphincsPlus_Haraka_256_Small
    | SphincsPlus_Haraka_256_Fast
    deriving stock (Show, Eq, Ord, Enum, Bounded)

sphincsPlusModeName :: SphincsPlusMode -> ByteString
sphincsPlusModeName SphincsPlus_SHA2_128_Small   = "SphincsPlus-sha2-128s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_128_Fast    = "SphincsPlus-sha2-128f-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_192_Small   = "SphincsPlus-sha2-192s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_192_Fast    = "SphincsPlus-sha2-192f-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_256_Small   = "SphincsPlus-sha2-256s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_256_Fast    = "SphincsPlus-sha2-256f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_128_Small  = "SphincsPlus-shake-128s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_128_Fast   = "SphincsPlus-shake-128f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_192_Small  = "SphincsPlus-shake-192s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_192_Fast   = "SphincsPlus-shake-192f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_256_Small  = "SphincsPlus-shake-256s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_256_Fast   = "SphincsPlus-shake-256f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_128_Small = "SphincsPlus-haraka-128s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_128_Fast  = "SphincsPlus-haraka-128f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_192_Small = "SphincsPlus-haraka-192s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_192_Fast  = "SphincsPlus-haraka-192f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_256_Small = "SphincsPlus-haraka-256s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_256_Fast  = "SphincsPlus-haraka-256f-r3.1"

-- NOTE: Could break into Hash, Parameter set, Prehash mode, but an enum is fine
data SLH_DSAMode
    = SLH_DSA_SHA2_128_Small
    | SLH_DSA_SHA2_128_Fast
    | SLH_DSA_SHA2_192_Small
    | SLH_DSA_SHA2_192_Fast
    | SLH_DSA_SHA2_256_Small
    | SLH_DSA_SHA2_256_Fast
    | SLH_DSA_SHAKE_128_Small
    | SLH_DSA_SHAKE_128_Fast
    | SLH_DSA_SHAKE_192_Small
    | SLH_DSA_SHAKE_192_Fast
    | SLH_DSA_SHAKE_256_Small
    | SLH_DSA_SHAKE_256_Fast
    | Prehash_SLH_DSA_SHA2_128_Small_with_SHA256
    | Prehash_SLH_DSA_SHA2_128_Fast_with_SHA256
    | Prehash_SLH_DSA_SHA2_192_Small_with_SHA512
    | Prehash_SLH_DSA_SHA2_192_Fast_with_SHA512
    | Prehash_SLH_DSA_SHA2_256_Small_with_SHA512
    | Prehash_SLH_DSA_SHA2_256_Fast_with_SHA512
    | Prehash_SLH_DSA_SHAKE_128_Small_with_SHAKE128
    | Prehash_SLH_DSA_SHAKE_128_Fast_with_SHAKE128
    | Prehash_SLH_DSA_SHAKE_192_Small_with_SHAKE256
    | Prehash_SLH_DSA_SHAKE_192_Fast_with_SHAKE256
    | Prehash_SLH_DSA_SHAKE_256_Small_with_SHAKE256
    | Prehash_SLH_DSA_SHAKE_256_Fast_with_SHAKE256
    deriving stock (Show, Eq, Ord, Enum, Bounded)

slh_dsaModeName :: SLH_DSAMode -> ByteString
slh_dsaModeName SLH_DSA_SHA2_128_Small  = "SLH-DSA-SHA2-128s"
slh_dsaModeName SLH_DSA_SHA2_128_Fast   = "SLH-DSA-SHA2-128f"
slh_dsaModeName SLH_DSA_SHA2_192_Small  = "SLH-DSA-SHA2-192s"
slh_dsaModeName SLH_DSA_SHA2_192_Fast   = "SLH-DSA-SHA2-192f"
slh_dsaModeName SLH_DSA_SHA2_256_Small  = "SLH-DSA-SHA2-256s"
slh_dsaModeName SLH_DSA_SHA2_256_Fast   = "SLH-DSA-SHA2-256f"
slh_dsaModeName SLH_DSA_SHAKE_128_Small = "SLH-DSA-SHAKE-128s"
slh_dsaModeName SLH_DSA_SHAKE_128_Fast  = "SLH-DSA-SHAKE-128f"
slh_dsaModeName SLH_DSA_SHAKE_192_Small = "SLH-DSA-SHAKE-192s"
slh_dsaModeName SLH_DSA_SHAKE_192_Fast  = "SLH-DSA-SHAKE-192f"
slh_dsaModeName SLH_DSA_SHAKE_256_Small = "SLH-DSA-SHAKE-256s"
slh_dsaModeName SLH_DSA_SHAKE_256_Fast  = "SLH-DSA-SHAKE-256f"
slh_dsaModeName Prehash_SLH_DSA_SHA2_128_Small_with_SHA256     = "Hash-SLH-DSA-SHA2-128s-with-SHA256"
slh_dsaModeName Prehash_SLH_DSA_SHA2_128_Fast_with_SHA256      = "Hash-SLH-DSA-SHA2-128f-with-SHA256"
slh_dsaModeName Prehash_SLH_DSA_SHA2_192_Small_with_SHA512     = "Hash-SLH-DSA-SHA2-192s-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_192_Fast_with_SHA512      = "Hash-SLH-DSA-SHA2-192f-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_256_Small_with_SHA512     = "Hash-SLH-DSA-SHA2-256s-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_256_Fast_with_SHA512      = "Hash-SLH-DSA-SHA2-256f-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_128_Small_with_SHAKE128  = "Hash-SLH-DSA-SHAKE-128s-with-SHAKE128"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_128_Fast_with_SHAKE128   = "Hash-SLH-DSA-SHAKE-128f-with-SHAKE128"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_192_Small_with_SHAKE256  = "Hash-SLH-DSA-SHAKE-192s-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_192_Fast_with_SHAKE256   = "Hash-SLH-DSA-SHAKE-192f-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_256_Small_with_SHAKE256  = "Hash-SLH-DSA-SHAKE-256s-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_256_Fast_with_SHAKE256   = "Hash-SLH-DSA-SHAKE-256f-with-SHAKE256"


{-
Helpers
-}

-- | Query-then-fill idiom for functions with a @(buf, *len)@ output pair.
-- Trims the result to the number of bytes actually written.
allocQueried :: (Ptr Word8 -> Ptr CSize -> IO CInt) -> IO ByteString
allocQueried f = mask_ $ do
    n <- queryBufferLength $ \ szPtr -> f Foreign.nullPtr szPtr
    alloca $ \ szPtr -> do
        poke szPtr (fromIntegral n)
        bytes <- allocInit ByteStringAllocator n $ \ fPtr ->
            withPtr fPtr $ \ bytesPtr ->
            throwBotanIfNegative_ $ f bytesPtr szPtr
        written <- peek szPtr
        return $!! ByteString.take (fromIntegral written) bytes

-- TODO: RE-DO THE LOADER HELPERS WITH MPFROM/TOINTEGER
