{-# LANGUAGE OverloadedStrings {-, CPP -}, CApiFFI #-}

module Botan.PubKey
( PrivKey(..)
, withPrivKey
, privKeyCreate
, generatePrivKey
, PKKeyTests(..)
, privKeyCheckKey
, PubKey(..)
, withPubKey
, PKType(..)
, pkTypeName
, PKScheme(..)
, pkSchemeType
, pkSchemeName
, pkSchemeParams
, pkSuggestedScheme
, XMSSParams(..)
, xmssName
, KyberMode(..)
, kyberModeName
, DilithiumMode(..)
, dilithiumModeName
, ClassicMcElieceParams(..)
, classicMcElieceParamsName
, FrodoKEMMode(..)
, frodoKEMModeName
, SphincsPlusMode(..)
, sphincsPlusModeName
, SLH_DSAMode(..)
, slh_dsaModeName
, ECGroup(..)
, ecGroupName
, DLGroup(..)
, dlGroupName
, EME(..)
, emeName
, EMSA(..)
, emsaName
---
, pkTypeIsSupported
) where

import Botan.Internal.Prelude
import Botan.RNG
import Botan.Hash
import Botan.Bindings.PubKey

import qualified Data.ByteString as ByteString

-- For the CApiFFI constants
-- NOTE: Did not work
-- #include <botan/build.h>
import Foreign.C.Types (CInt(..))

{-
Bindings Memorized instance
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

{-
PrivKey functions
-}

privKeyCreate :: PKScheme -> RNG -> IO PrivKey
privKeyCreate pk rng = ByteString.useAsCString (pkSchemeName pk) $ \ namePtr ->
    ByteString.useAsCString (pkSchemeParams pk) $ \ paramsPtr ->
    withRNG rng $ \ botanRNG ->
        createBotan @PrivKey $ \ outPtr -> botan_privkey_create
            outPtr
            (ConstPtr namePtr)
            (ConstPtr paramsPtr)
            botanRNG
            

generatePrivKey :: PKScheme -> IO PrivKey
generatePrivKey pk = privKeyCreate pk userThreadsafeRNG

data PKKeyTests
    = PKNormalTests
    | PKExpensiveTests

pkKeyTestFlags :: PKKeyTests -> Word32
pkKeyTestFlags PKNormalTests    = BOTAN_CHECK_KEY_NORMAL_TESTS
pkKeyTestFlags PKExpensiveTests = BOTAN_CHECK_KEY_EXPENSIVE_TESTS

-- TODO: Probably catch -1 (INVALID_INPUT), return Bool
-- | Check the validity of a private key
-- NOTE: This function may or may not be deprecated - it has been removed from
-- documentation, but is still present in the code. I
privKeyCheckKey
    :: PrivKey          -- ^ __key__
    -> RNG              -- ^ __rng__
    -> PKKeyTests       -- ^ __flags__
    -> IO ()
privKeyCheckKey prk rng flags = withPrivKey prk $ \ prkPtr -> do
    withRNG rng $ \ botanRNG -> do
        throwBotanIfNegative_ $ botan_privkey_check_key prkPtr botanRNG (pkKeyTestFlags flags)

checkPrivKey :: PrivKey -> PKKeyTests -> IO Bool
checkPrivKey prk flags = withPrivKey prk $ \ prkPtr -> do
    withRNG userThreadsafeRNG $ \ botanRNG -> do
        throwBotanCatchingInvalidInput $ botan_privkey_check_key prkPtr botanRNG (pkKeyTestFlags flags)

-- -- NOTE: Expectes PKCS #8 / PEM structure
-- -- botan_privkey_export -> null password? and botan_privkey_export_encrypted_... -> use a password?
-- -- NOTE: This is probably a bad implementation; null pointer and empty string are different
-- --  and unencrypted is not the same as encrypted with "" as a pasword
-- --  We'll fix this by having privKeyLoad and privKeyLoadEncrypted be separate functions
-- {- |
-- Input currently assumed to be PKCS #8 structure;
-- Set password to NULL to indicate no encryption expected
-- Starting in 2.8.0, the rng parameter is unused and may be set to null
-- -}
-- privKeyLoad
--     :: ByteString   -- ^ __bits[]__
--     -> ByteString   -- ^ __password__
--     -> IO PrivKey   -- ^ __key__
-- privKeyLoad bits password = asBytesLen bits $ \ bitsPtr bitsLen -> do
--     let asCStringNullable str act = if ByteString.null str
--         then act nullPtr
--         else asCString str act
--     asCStringNullable password $ \ passwordPtr -> do
--         createPrivKey $ \ out -> botan_privkey_load
--             out
--             (MkBotanRNG nullPtr)
--             (ConstPtr bitsPtr)
--             bitsLen
--             (ConstPtr passwordPtr)

-- data PrivKeyExportFlags =
--     PrivKeyExportDER
--   | PrivKeyExportPEM

-- privKeyExportFlags :: PrivKeyExportFlags -> Word32
-- privKeyExportFlags PrivKeyExportDER = BOTAN_PRIVKEY_EXPORT_FLAG_DER
-- privKeyExportFlags PrivKeyExportPEM = BOTAN_PRIVKEY_EXPORT_FLAG_PEM

-- -- NOTE: Different from allocBytesQuerying / INSUFFICIENT_BUFFER_SPACE
-- {- |
-- On input *out_len is number of bytes in out[]
-- On output *out_len is number of bytes written (or required)
-- If out is not big enough no output is written, *out_len is set and 1 is returned
-- Returns 0 on success and sets
-- If some other error occurs a negative integer is returned.
-- -}
-- privKeyExport
--     :: PrivKey              -- ^ __key__
--     -> PrivKeyExportFlags   -- ^ __flags__
--     -> IO ByteString        -- ^ __out[]__
-- privKeyExport sk flags = withPrivKey sk $ \ skPtr -> do
--     alloca $ \szPtr -> do
--         poke szPtr 0
--         -- NOTE: Presumed be -1
--         _ <- botan_privkey_export skPtr nullPtr szPtr (privKeyExportFlags flags)
--         sz <- peek szPtr
--         allocBytes (fromIntegral sz) $ \ bytesPtr -> do
--             throwBotanIfNegative_ $ botan_privkey_export skPtr bytesPtr szPtr (privKeyExportFlags flags)

-- -- TODO:
-- -- View the private key's DER encoding
-- -- privKeyViewDER
-- --         :: BotanPrivKey                         -- ^ __key__
-- --         -> BotanViewContext ctx                 -- ^ __ctx__
-- --         -> FunPtr (BotanViewBinCallback ctx)    -- ^ __view__
-- --         -> IO CInt

-- -- TODO:
-- -- View the private key's PEM encoding
-- -- privKeyViewPEM
-- --         :: BotanPrivKey                         -- ^ __key__
-- --         -> BotanViewContext ctx                 -- ^ __ctx__
-- --         -> FunPtr (BotanViewStrCallback ctx)    -- ^ __view__
-- --         -> IO CInt

-- privKeyAlgoName
--     :: PrivKey          -- ^ __key__
--     -> IO ByteString    -- ^ __out[]__
-- privKeyAlgoName = mkGetCString withPrivKey botan_privkey_algo_name

-- -- TODO:
-- -- privKeyExportEncryptedPBKDFMsec
-- --     :: PrivKey
-- --     -> RNG
-- --     -> ByteString   -- Passphrase
-- --     -> Word32       -- Msec runtime
-- --     -> ByteString   -- Cipher algo
-- --     -> ByteString   -- PBKDF algo
-- --     -> Word32       -- Flags
-- --     -> IO ByteString
-- -- privKeyExportEncryptedPBKDFMsec = undefined

-- -- TODO:
-- -- privKeyExportEncryptedPBKDFIter
-- --     :: PrivKey
-- --     -> RNG
-- --     -> ByteString   -- Passphrase
-- --     -> CSize        -- Iterations
-- --     -> ByteString   -- Cipher algo
-- --     -> ByteString   -- PBKDF algo
-- --     -> Word32       -- Flags
-- --     -> IO ByteString
-- -- privKeyExportEncryptedPBKDFIter = undefined

-- privKeyExportPubKey
--     :: PrivKey      -- ^ __in__
--     -> IO PubKey    -- ^ __out__
-- privKeyExportPubKey = mkCreateObjectWith createPubKey withPrivKey botan_privkey_export_pubkey

-- type PubKeyExportFlags = PrivKeyExportFlags

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

{-
PubKey Functions
-}

-- pubKeyLoad
--     :: ByteString   -- ^ __bits[]__
--     -> IO PubKey    -- ^ __key__
-- pubKeyLoad = mkCreateObjectCBytesLen createPubKey botan_pubkey_load


-- -- NOTE: Different from allocBytesQuerying / INSUFFICIENT_BUFFER_SPACE
-- pubKeyExport
--     :: PubKey               -- ^ __key__
--     -> PubKeyExportFlags    -- ^ __flags__
--     -> IO ByteString        -- ^ __out[]__
-- pubKeyExport pk flags = withPubKey pk $ \ pkPtr -> do
--     alloca $ \szPtr -> do
--         poke szPtr 0
--         -- NOTE: Presumed be -1
--         _ <- botan_pubkey_export pkPtr nullPtr szPtr (privKeyExportFlags flags)
--         sz <- peek szPtr
--         allocBytes (fromIntegral sz) $ \ bytesPtr -> do
--             throwBotanIfNegative_ $ botan_pubkey_export pkPtr bytesPtr szPtr (privKeyExportFlags flags)


-- pubKeyAlgoName
--     :: PubKey           -- ^ __key__
--     -> IO ByteString    -- ^ __out[]__
-- pubKeyAlgoName = mkGetCString withPubKey botan_pubkey_algo_name

-- pubKeyCheckKey ::
--      PubKey           -- ^ __key__
--   -> RNG              -- ^ __rng__
--   -> CheckKeyFlags    -- ^ __flags__
--   -> IO Bool
-- pubKeyCheckKey pk rng flags =
--     withPubKey pk $ \ pkPtr ->
--     withRNG rng $ \ botanRNG ->
--     throwBotanCatchingInvalidInput $ botan_pubkey_check_key pkPtr botanRNG (checkKeyFlags flags)

-- -- Annoying - this mixes cint and csize
-- --  I need to consolidate getsize / getint
-- pubKeyEstimatedStrength
--     :: PubKey   -- ^ __key__
--     -> IO Int   -- ^ __estimate__
-- pubKeyEstimatedStrength pk = mkGetSize withPubKey botan_pubkey_estimated_strength pk

-- pubKeyFingerprint
--     :: PubKey           -- ^ __key__
--     -> HashName         -- ^ __hash__
--     -> IO ByteString    -- ^ __out[]__
-- pubKeyFingerprint pk algo = withPubKey pk $ \ pkPtr -> do
--     asCString algo $ \ algoPtr -> do
--         allocBytesQuerying $ \ outPtr outLen -> botan_pubkey_fingerprint
--             pkPtr
--             (ConstPtr algoPtr)
--             outPtr
--             outLen

-- -- | Get arbitrary named fields from public or private keys
-- pubKeyGetField
--     :: MP           -- ^ __output__
--     -> PubKey       -- ^ __key__
--     -> ByteString   -- ^ __field_name__
--     -> IO ()
-- pubKeyGetField mp pk field = withMP mp $ \ mpPtr -> do
--     withPubKey pk $ \ pkPtr -> do
--         asCString field $ \ fieldPtr -> do
--             throwBotanIfNegative_ $ botan_pubkey_get_field
--                 mpPtr
--                 pkPtr
--                 (ConstPtr fieldPtr)

-- -- | Get arbitrary named fields from public or private keys
-- privKeyGetField
--     :: MP           -- ^ __output__
--     -> PrivKey      -- ^ __key__
--     -> ByteString   -- ^ __field_name__
--     -> IO ()
-- privKeyGetField mp sk field = withMP mp $ \ mpPtr -> do
--     withPrivKey sk $ \ skPtr -> do
--         asCString field $ \ fieldPtr -> do
--             throwBotanIfNegative_ $ botan_privkey_get_field
--                 mpPtr
--                 skPtr
--                 (ConstPtr fieldPtr)

-- -- Helpers

-- mkPrivKeyLoad1_name
--     :: (Ptr BotanPrivKey -> BotanMP -> ConstPtr CChar -> IO CInt)
--     -> MP -> ByteString -> IO PrivKey
-- mkPrivKeyLoad1_name load a name = withMP a $ \ aPtr -> do
--     asCString name $ \ namePtr -> do
--         createPrivKey $ \ out -> load out aPtr (ConstPtr namePtr)

-- mkPrivKeyLoad3
--     :: (Ptr BotanPrivKey -> BotanMP -> BotanMP -> BotanMP -> IO CInt)
--     -> MP -> MP -> MP -> IO PrivKey
-- mkPrivKeyLoad3 load a b c = withMany withMP [a,b,c] $ \case
--     [aPtr,bPtr,cPtr] -> do
--       createPrivKey $ \ out -> load out aPtr bPtr cPtr
--     _ -> error "mkPrivKeyLoad3: impossible"

-- mkPrivKeyLoad4
--     :: (Ptr BotanPrivKey -> BotanMP -> BotanMP -> BotanMP -> BotanMP -> IO CInt)
--     -> MP -> MP -> MP -> MP -> IO PrivKey
-- mkPrivKeyLoad4 load a b c d = withMany withMP [a,b,c,d] $ \case
--     [aPtr,bPtr,cPtr,dPtr] -> do
--       createPrivKey $ \ out -> load out aPtr bPtr cPtr dPtr
--     _ -> error "mkPrivKeyLoad4: impossible"

-- --

-- mkPubKeyLoad2
--     :: (Ptr BotanPubKey -> BotanMP -> BotanMP -> IO CInt)
--     -> MP -> MP -> IO PubKey
-- mkPubKeyLoad2 load a b = withMany withMP [a,b] $ \case
--     [aPtr,bPtr] -> do
--       createPubKey $ \ out -> load out aPtr bPtr
--     _ -> error "mkPubKeyLoad2: impossible"

-- mkPubKeyLoad2_name
--     :: (Ptr BotanPubKey -> BotanMP -> BotanMP -> ConstPtr CChar -> IO CInt)
--     -> MP -> MP -> ByteString -> IO PubKey
-- mkPubKeyLoad2_name load x y name = withMany withMP [x,y] $ \case
--     [xPtr,yPtr] -> do
--       asCString name $ \ namePtr -> do
--         createPubKey $ \ out -> load out xPtr yPtr (ConstPtr namePtr)
--     _ -> error "mkPubKeyLoad2_name: impossible"

-- mkPubKeyLoad3
--     :: (Ptr BotanPubKey -> BotanMP -> BotanMP -> BotanMP -> IO CInt)
--     -> MP -> MP -> MP -> IO PubKey
-- mkPubKeyLoad3 load a b c = withMany withMP [a,b,c] $ \case
--     [aPtr,bPtr,cPtr] -> do
--       createPubKey $ \ out -> load out aPtr bPtr cPtr
--     _ -> error "mkPubKeyLoad3: impossible"

-- mkPubKeyLoad4
--     :: (Ptr BotanPubKey -> BotanMP -> BotanMP -> BotanMP -> BotanMP -> IO CInt)
--     -> MP -> MP -> MP -> MP -> IO PubKey
-- mkPubKeyLoad4 load a b c d = withMany withMP [a,b,c,d] $ \case
--     [aPtr,bPtr,cPtr,dPtr] -> do
--       createPubKey $ \ out -> load out aPtr bPtr cPtr dPtr
--     _ -> error "mkPubKeyLoad4: impossible"

-- withMany ::
--      (forall a . object -> (cobject -> IO a) -> IO a)
--   -> [object]
--   -> ([cobject] -> IO b)
--   -> IO b
-- withMany _withObject []         act = act []
-- withMany withObject  (obj:objs) act = withObject obj $ \ cobj -> withMany withObject objs (act . (cobj:))













{-
Public Key types
-}

-- NOTE: Key operations throw an error -31 for unsupported key types, at least,
-- privKeyCheckKey does - probably because it returns a null pointer if not supported
-- Unsupported key types (for me) are:
-- - ML_DSA - 3.5
-- - ML_KEM - 3.5
-- - ClassicMcEliece - 3.7 (McEliece is being removed in 4.0)
-- - SPHINCSPlusType
-- - SLH_DSAType - 3.5
-- However, I am using 3.5 so only ClassicMcElieceType should be missing.
-- But looking at my botan build config the only one I do have is sphincs, so
-- its a mystery why that one is disabled but not the others.
-- NOTE: Ed448 / X448 were added in 3.4
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

{-
import Botan.PubKey
pkTypes = [minBound..maxBound] :: [PKType]
-- forM_ pkTypes print
forM_ pkTypes $ \ pk -> putStrLn $ show pk <> " " <> show (pkTypeIsSupported pk)
pkSchemes = fmap pkSuggestedScheme pkTypes
forM_ pkSchemes print
keys <- forM pkSchemes generatePrivKey
pkCheckKey k = privKeyCheckKey k userThreadsafeRNG PKNormalTests
checkKeys = forM_ keys pkCheckKey
-}
-- > testPKType pkType = generatePrivKey (pkSuggestedScheme pkType) >>= (\ k -> privKeyCheckKey k userThreadsafeRNG PKNormalTests)

-- TODO: Push down new constants to botan-bindings
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
pkSchemeParams (SphincsPlus params)    = sphincsPlusModeName params
pkSchemeParams (SLH_DSA params)        = slh_dsaModeName params

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

-- NOTE: To make this work, we need to import botan/build.h EXCEPT
-- it has a indented defined in an #ifndef BOTAN_DLL that causes the strict CPP
-- to fail. Instead, we will import constants
-- pkTypeIsSupported :: PKType -> Bool
-- -- TODO: Use the BOTAN_HAS_ defines, eg
-- #if defined(BOTAN_HAS_X25519)
-- pkSupported X25519Type = True
-- #endif
-- #if defined(BOTAN_HAS_X448)
-- pkSupported X448Type = True
-- #endif
-- #if defined(BOTAN_HAS_RSA)
-- pkSupported RSAType = True
-- #endif
-- #if defined(BOTAN_HAS_SM2)
-- pkSupported SM2Type = True
-- #endif
-- #if defined(BOTAN_HAS_MCELIECE)
-- pkSupported McElieceType = True
-- #endif
-- #if defined(BOTAN_HAS_CLASSICMCELIECE)
-- pkSupported ClassicMcElieceType = True
-- #endif
-- #if defined(BOTAN_HAS_FRODOKEM) || defined(BOTAN_HAS_FRODOKEM_SHAKE) || defined(BOTAN_HAS_FRODOKEM_AES)
-- pkSupported FrodoKEMType = True
-- #endif
-- #if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
-- pkSupported KyberType = True
-- #endif
-- #if defined(BOTAN_HAS_ML_KEM)
-- pkSupported ML_KEMType = True
-- #endif
-- #if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
-- pkSupported DilithiumType = True
-- #endif
-- #if defined(BOTAN_HAS_ML_DSA)
-- pkSupported ML_DSAType = True
-- #endif
-- #if defined(BOTAN_HAS_HSS_LMS)
-- pkSupported HSS_LMSType = True
-- #endif
-- #if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
-- pkSupported SphincsPlusType = True
-- #endif
-- #if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
-- pkSupported SLH_DSAType = True
-- #endif
-- #if defined(BOTAN_HAS_XMSS_RFC8391)
-- pkSupported XMSSType = True
-- #endif
-- #if defined(BOTAN_HAS_ED25519)
-- pkSupported Ed25519Type = True
-- #endif
-- #if defined(BOTAN_HAS_ED448)
-- pkSupported Ed448Type = True
-- #endif
-- #if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
-- pkSupported ECDSAType = True ()
-- pkSupported ECKCDSAType = True
-- pkSupported ECGDSAType = True
-- #endif
-- #if defined(BOTAN_HAS_GOST_34_10_2001)
-- pkSupported GOST_34_10Type = True
-- #endif
-- #if defined(BOTAN_HAS_DL_GROUP) && defined(BOTAN_HAS_DIFFIE_HELLMAN)
-- pkSupported DHType = True
-- #endif
-- #if defined(BOTAN_HAS_DL_GROUP) && defined(BOTAN_HAS_ELGAMAL)
-- pkSupported DSAType = True
-- #endif
-- #if defined(BOTAN_HAS_DL_GROUP) && defined(BOTAN_HAS_ELGAMAL)
-- pkSupported ElGamalType = True
-- #endif
-- pkTypeIsSupported _ = False

-- NOTE: According to pk_algs.cpp, create_ec_private_key, gost and sm2 are indeed included in EC algs as expected

-- Since the indented #define doesn't allow us to use the constants directly for
-- conditional compilation, we will import the defines and allow the compiler to
-- elide things via constant folding

-- Prime factorization
foreign import capi safe "botan/build.h value BOTAN_HAS_RSA" botan_has_rsa :: CInt

-- DL
foreign import capi safe "botan/build.h value BOTAN_HAS_DL_GROUP" botan_has_dl_group :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_DIFFIE_HELLMAN" botan_has_diffie_hellman :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_DSA" botan_has_dsa :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ELGAMAL" botan_has_elgamal :: CInt

-- ECC
foreign import capi safe "botan/build.h value BOTAN_HAS_ECC_GROUP" botan_has_ecc_group :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO" botan_has_ecc_public_key_crypto :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ECDH" botan_has_ecdh :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ECDSA" botan_has_ecdsa :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ECKCDSA" botan_has_eckcdsa :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ECGDSA" botan_has_ecgdsa :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_SM2" botan_has_sm2 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_GOST_34_10_2001" botan_has_gost_34_10_2001 :: CInt

-- Named curves
foreign import capi safe "botan/build.h value BOTAN_HAS_X25519" botan_has_x25519 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_X448" botan_has_x448 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ED25519" botan_has_ed25519 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ED448" botan_has_ed448 :: CInt

-- Post-quantum
foreign import capi safe "botan/build.h value BOTAN_HAS_MCELIECE" botan_has_mceliece :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_CLASSICMCELIECE" botan_has_classicmceliece :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_FRODOKEM" botan_has_frodoKEM :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_KYBER" botan_has_kyber :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_KYBER_90S" botan_has_kyber_90s :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ML_KEM" botan_has_ml_kem :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_DILITHIUM" botan_has_dilithium :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_ML_DSA" botan_has_ml_dsa :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_HSS_LMS" botan_has_hss_lms :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2" botan_has_sphincs_plus_with_sha2 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE" botan_has_sphincs_plus_with_shake :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_SLH_DSA_WITH_SHA2" botan_has_slh_dsa_with_sha2 :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_SLH_DSA_WITH_SHAKE" botan_has_slh_dsa_with_shake :: CInt
foreign import capi safe "botan/build.h value BOTAN_HAS_XMSS_RFC8391" botan_has_xmss_rfc8391 :: CInt


-- TODO: Also use has_dl_group, has_ecc_group
-- Strike that? new botan_ec_group_t added in 3.8
pkTypeIsSupported :: PKType -> Bool
pkTypeIsSupported X25519Type = botan_has_x25519 > 0
pkTypeIsSupported X448Type = botan_has_x448 > 0
pkTypeIsSupported RSAType = botan_has_rsa > 0
pkTypeIsSupported McElieceType = botan_has_mceliece > 0
pkTypeIsSupported ClassicMcElieceType = botan_has_classicmceliece > 0
pkTypeIsSupported FrodoKEMType = botan_has_frodoKEM > 0
pkTypeIsSupported KyberType = botan_has_kyber > 0 || botan_has_kyber_90s > 0
pkTypeIsSupported ML_KEMType = botan_has_ml_kem > 0
pkTypeIsSupported DilithiumType = botan_has_dilithium > 0
pkTypeIsSupported ML_DSAType = botan_has_ml_dsa > 0
pkTypeIsSupported HSS_LMSType = botan_has_hss_lms > 0
pkTypeIsSupported SphincsPlusType = botan_has_sphincs_plus_with_sha2 > 0 || botan_has_sphincs_plus_with_shake > 0
pkTypeIsSupported SLH_DSAType = botan_has_slh_dsa_with_sha2 > 0 || botan_has_slh_dsa_with_shake > 0
pkTypeIsSupported XMSSType = botan_has_xmss_rfc8391 > 0
pkTypeIsSupported Ed25519Type = botan_has_ed25519 > 0
pkTypeIsSupported Ed448Type = botan_has_ed448 > 0
pkTypeIsSupported ECDSAType = botan_has_ecc_public_key_crypto > 0 && botan_has_ecdsa > 0
pkTypeIsSupported ECKCDSAType = botan_has_ecc_public_key_crypto > 0 && botan_has_eckcdsa > 0
pkTypeIsSupported ECGDSAType = botan_has_ecc_public_key_crypto > 0 && botan_has_ecgdsa > 0
pkTypeIsSupported SM2Type = botan_has_ecc_public_key_crypto > 0 && botan_has_sm2 > 0
pkTypeIsSupported GOST_34_10Type = botan_has_ecc_public_key_crypto > 0 && botan_has_gost_34_10_2001 > 0
pkTypeIsSupported DHType = botan_has_diffie_hellman > 0
pkTypeIsSupported ECDHType = botan_has_ecdh > 0
pkTypeIsSupported DSAType = botan_has_dsa > 0
pkTypeIsSupported ElGamalType = botan_has_elgamal > 0

{-
Supporting parameter types
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
    deriving stock (Show, Eq, Ord)

xmssName :: XMSSParams -> ByteString
xmssName XMSS_SHA2_10_256   = BOTAN_XMSS_SHA2_10_256
xmssName XMSS_SHA2_16_256   = BOTAN_XMSS_SHA2_16_256
xmssName XMSS_SHA2_20_256   = BOTAN_XMSS_SHA2_20_256
xmssName XMSS_SHA2_10_512   = BOTAN_XMSS_SHA2_10_512
xmssName XMSS_SHA2_16_512   = BOTAN_XMSS_SHA2_16_512
xmssName XMSS_SHA2_20_512   = BOTAN_XMSS_SHA2_20_512
xmssName XMSS_SHAKE_10_256  = BOTAN_XMSS_SHAKE_10_256
xmssName XMSS_SHAKE_16_256  = BOTAN_XMSS_SHAKE_16_256
xmssName XMSS_SHAKE_20_256  = BOTAN_XMSS_SHAKE_20_256
xmssName XMSS_SHAKE_10_512  = BOTAN_XMSS_SHAKE_10_512
xmssName XMSS_SHAKE_16_512  = BOTAN_XMSS_SHAKE_16_512
xmssName XMSS_SHAKE_20_512  = BOTAN_XMSS_SHAKE_20_512
xmssName XMSS_SHA2_10_192   = "XMSS-SHA2_10_192"
xmssName XMSS_SHA2_16_192   = "XMSS-SHA2_16_192"
xmssName XMSS_SHA2_20_192   = "XMSS-SHA2_20_192"
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
    deriving stock (Show, Eq, Ord)

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
    deriving stock (Show, Eq, Ord)

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



{-
Supporting parameter types
-}

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
    deriving stock (Show, Eq, Ord)

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
    deriving stock (Show, Eq, Ord)

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
    deriving stock (Show, Eq, Ord)

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
    deriving stock (Show, Eq, Ord)

frodoKEMModeName :: FrodoKEMMode -> ByteString
frodoKEMModeName FrodoKEM640_SHAKE          = "FrodoKEM-640-SHAKE"
frodoKEMModeName FrodoKEM976_SHAKE          = "FrodoKEM-976-SHAKE"
frodoKEMModeName FrodoKEM1344_SHAKE         = "FrodoKEM-1344-SHAKE"
frodoKEMModeName EphemeralFrodoKEM640_SHAKE  = "eFrodoKEM-640-SHAKE"
frodoKEMModeName EphemeralFrodoKEM976_SHAKE  = "eFrodoKEM-976-SHAKE"
frodoKEMModeName EphemeralFrodoKEM1344_SHAKE = "eFrodoKEM-1344-SHAKE"
frodoKEMModeName FrodoKEM640_AES            = "FrodoKEM-640-AES"
frodoKEMModeName FrodoKEM976_AES            = "FrodoKEM-976-AES"
frodoKEMModeName FrodoKEM1344_AES           = "FrodoKEM-1344-AES"
frodoKEMModeName EphemeralFrodoKEM640_AES  = "eFrodoKEM-640-AES"
frodoKEMModeName EphemeralFrodoKEM976_AES  = "eFrodoKEM-976-AES"
frodoKEMModeName EphemeralFrodoKEM1344_AES = "eFrodoKEM-1344-AES"

-- NOTE: Could break into Hash, Parameter set, but enum is fine
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
   deriving stock (Show, Eq, Ord)

sphincsPlusModeName :: SphincsPlusMode -> ByteString
sphincsPlusModeName SphincsPlus_SHA2_128_Small = "SphincsPlus-sha2-128s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_128_Fast  = "SphincsPlus-sha2-128f-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_192_Small = "SphincsPlus-sha2-192s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_192_Fast  = "SphincsPlus-sha2-192f-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_256_Small = "SphincsPlus-sha2-256s-r3.1"
sphincsPlusModeName SphincsPlus_SHA2_256_Fast  = "SphincsPlus-sha2-256f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_128_Small = "SphincsPlus-shake-128s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_128_Fast  = "SphincsPlus-shake-128f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_192_Small = "SphincsPlus-shake-192s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_192_Fast  = "SphincsPlus-shake-192f-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_256_Small = "SphincsPlus-shake-256s-r3.1"
sphincsPlusModeName SphincsPlus_SHAKE_256_Fast  = "SphincsPlus-shake-256f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_128_Small = "SphincsPlus-haraka-128s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_128_Fast  = "SphincsPlus-haraka-128f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_192_Small = "SphincsPlus-haraka-192s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_192_Fast  = "SphincsPlus-haraka-192f-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_256_Small = "SphincsPlus-haraka-256s-r3.1"
sphincsPlusModeName SphincsPlus_Haraka_256_Fast  = "SphincsPlus-haraka-256f-r3.1"

-- NOTE: Could break into Hash, Parameter set, Prehash mode, but enum is fine
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
    deriving stock (Show, Eq, Ord)

slh_dsaModeName :: SLH_DSAMode -> ByteString
slh_dsaModeName SLH_DSA_SHA2_128_Small = "SLH-DSA-SHA2-128s"
slh_dsaModeName SLH_DSA_SHA2_128_Fast  = "SLH-DSA-SHA2-128f"
slh_dsaModeName SLH_DSA_SHA2_192_Small = "SLH-DSA-SHA2-192s"
slh_dsaModeName SLH_DSA_SHA2_192_Fast  = "SLH-DSA-SHA2-192f"
slh_dsaModeName SLH_DSA_SHA2_256_Small = "SLH-DSA-SHA2-256s"
slh_dsaModeName SLH_DSA_SHA2_256_Fast  = "SLH-DSA-SHA2-256f"
slh_dsaModeName SLH_DSA_SHAKE_128_Small = "SLH-DSA-SHAKE-128s"
slh_dsaModeName SLH_DSA_SHAKE_128_Fast  = "SLH-DSA-SHAKE-128f"
slh_dsaModeName SLH_DSA_SHAKE_192_Small = "SLH-DSA-SHAKE-192s"
slh_dsaModeName SLH_DSA_SHAKE_192_Fast  = "SLH-DSA-SHAKE-192f"
slh_dsaModeName SLH_DSA_SHAKE_256_Small = "SLH-DSA-SHAKE-256s"
slh_dsaModeName SLH_DSA_SHAKE_256_Fast  = "SLH-DSA-SHAKE-256f"
slh_dsaModeName Prehash_SLH_DSA_SHA2_128_Small_with_SHA256 = "Hash-SLH-DSA-SHA2-128s-with-SHA256"
slh_dsaModeName Prehash_SLH_DSA_SHA2_128_Fast_with_SHA256  = "Hash-SLH-DSA-SHA2-128f-with-SHA256"
slh_dsaModeName Prehash_SLH_DSA_SHA2_192_Small_with_SHA512 = "Hash-SLH-DSA-SHA2-192s-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_192_Fast_with_SHA512 = "Hash-SLH-DSA-SHA2-192f-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_256_Small_with_SHA512 = "Hash-SLH-DSA-SHA2-256s-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHA2_256_Fast_with_SHA512 = "Hash-SLH-DSA-SHA2-256f-with-SHA512"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_128_Small_with_SHAKE128 = "Hash-SLH-DSA-SHAKE-128s-with-SHAKE128"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_128_Fast_with_SHAKE128 = "Hash-SLH-DSA-SHAKE-128f-with-SHAKE128"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_192_Small_with_SHAKE256 = "Hash-SLH-DSA-SHAKE-192s-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_192_Fast_with_SHAKE256 = "Hash-SLH-DSA-SHAKE-192f-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_256_Small_with_SHAKE256 = "Hash-SLH-DSA-SHAKE-256s-with-SHAKE256"
slh_dsaModeName Prehash_SLH_DSA_SHAKE_256_Fast_with_SHAKE256 = "Hash-SLH-DSA-SHAKE-256f-with-SHAKE256"
{-

New UPDATED Algorithms / parameters / defautls

BOTAN_HAS_X25519
- alg_name: "X25519" or "Curve25519"
- params: none
- return: X25519_PrivateKey

BOTAN_HAS_X448
- alg_name: "X448"
- params: none
- return: X448_PrivateKey

BOTAN_HAS_RSA
- alg_name: "RSA"
- params: modulus_bits, default: "3072"
- return: RSA_PrivateKey

BOTAN_HAS_MCELIECE
- alg_name: "McEliece"
- params: n,t, default: "2960,57"
    - NOTE: n,t are Word32 values
- return: McEliece_PrivateKey

BOTAN_HAS_CLASSICMCELIECE
- alg_name: "ClassicMcEliece"
- params: cmce_params_set, default: ClassicMcEliece_6960119f
- return: Classic_McEliece_PrivateKey

-- NOTE: Yoinked from: cmce_parameter_set.h
-- NOTE: Name can be the full string eg `ClassicMcEliece_348864` or just the
-- trailing value eg `348864`
data ClassicMcElieceParameterSet
    = ClassicMcEliece_348864,   // NIST
    | ClassicMcEliece_348864f,  // NIST
    | ClassicMcEliece_460896,   // NIST
    | ClassicMcEliece_460896f,  // NIST
    | ClassicMcEliece_6688128,     // ISO + NIST
    | ClassicMcEliece_6688128f,    // ISO + NIST
    | ClassicMcEliece_6688128pc,   // ISO
    | ClassicMcEliece_6688128pcf,  // ISO
    | ClassicMcEliece_6960119,     // ISO + NIST
    | ClassicMcEliece_6960119f,    // ISO + NIST
    | ClassicMcEliece_6960119pc,   // ISO
    | ClassicMcEliece_6960119pcf,  // ISO
    | ClassicMcEliece_8192128,     // ISO + NIST
    | ClassicMcEliece_8192128f,    // ISO + NIST
    | ClassicMcEliece_8192128pc,   // ISO
    | ClassicMcEliece_8192128pcf,  // ISO

BOTAN_HAS_FRODOKEM, BOTAN_HAS_FRODOKEM_SHAKE, BOTAN_HAS_FRODOKEM_AES
- alg_name: "FrodoKEM"
- params: FrodoKEMMode, default: FrodoKEM976_SHAKE
- return: FrodoKEM_PrivateKey

-- NOTE: Yoinked from: frodo_mode.h
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

BOTAN_HAS_KYBER, BOTAN_HAS_KYBER_90S
- alg_name: "Kyber"
- params: KyberMode, default: Kyber1024_R3
- return: Kyber_PrivateKey

-- NOTE: Yoinked from: kyber.h
data KyberMode
    = Kyber512_R3  -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    | Kyber768_R3  -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    | Kyber1024_R3 -- Deprecated: Kyber NIST Round 3 - use ML-KEM
    -- | Kyber512  -- Synonym for R3, ignore
    -- | Kyber768  -- Synonym for R3, ignore
    -- | Kyber1024 -- Synonym for R3, ignore
    | ML_KEM_512
    | ML_KEM_768
    | ML_KEM_1024
    | Kyber512_90s  -- Deprecated: Kyber 90s mode
    | Kyber768_90s  -- Deprecated: Kyber 90s mode
    | Kyber1024_90s -- Deprecated: Kyber 90s mode


BOTAN_HAS_ML_KEM
- alg_name: "ML-KEM"
- params: ML_KEM_Mode, default: ML_KEM_768
- return: ML_KEM_PrivateKey

-- NOTE: ML_KEM_Mode and ML_KEM_PrivateKey are synonyms for KyberMode and Kyber_PrivateKey
data ML_KEM_Mode
  = ML_KEM_512
  | ML_KEM_768
  | ML_KEM_1024

BOTAN_HAS_DILITHIUM, BOTAN_HAS_DILITHIUM_AES
- alg_name: "Dilithium" or "Dilithium-<mode>"
- params: DilithiumMode, default: Dilithium6x5
- return: Dilithium_PrivateKey

-- NOTE: Yoinked from: dilithium.h
-- NOTE: Strings are formatted as `Dilithium-NxM-r3`, `Dilithium-NxM-AES-r3`, or `ML-DSA-NxM`
data DilithiumMode
    = Dilithium4x4     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium4x4_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium6x5     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium6x5_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium8x7     -- Deprecated: Dilithium R3 - use ML-DSA
    | Dilithium8x7_AES -- Deprecated: Dilithium R3 - use ML-DSA
    | ML_DSA_4x4
    | ML_DSA_6x5
    | ML_DSA_8x7

BOTAN_HAS_ML_DSA
- alg_name: "ML-DSA"
- params: ML_DSA_Mode, default: ML_DSA_6x5
- return: ML_DSA_PrivateKey

-- NOTE: ML_DSA_Mode and ML_DSA_PrivateKey are synonyms for DilithiumMode and Dilithium_PrivateKey
data ML_DSA_Mode
    = ML_DSA_4x4
    | ML_DSA_6x5
    | ML_DSA_8x7

BOTAN_HAS_HSS_LMS
- alg_name: "HSS-LMS"
- params: HSS_LMS_Mode, default: SHA-256,HW(10,1)
    - Hash function, node bytes, tree height?
- return: HSS_LMS_PrivateKey

-- TODO: HSS_LMS
-- NOTE: Yoinked from: lms.h
-- NOTE: String formatted as eg `hash,HW(h,w)`
-- But its more complicated because multiple HW layers are allowed, eg:
-- - `HSS-LMS(SHA-256,HW(5,1),HW(5,1))` to use SHA-256 in a two-layer HSS instance with a LMS tree height 5 and w=1
-- NOTE: Valid values per RFC-8554 are:
-- - hash: 'SHA-256', 'Truncated(SHA-256,192)', 'SHAKE-256(256)', SHAKE-256(192)
-- - h: '5', '10', '15', '20', '25'
-- - w: '1', '2', '4', '8'
-- Plus its a stateful algorithm and stateless algorithms are preferred for
-- reasons of safety and ease of use, so this is low priority
data 
   // SHA-256 based
   SHA256_M32_H5 = 0x05,
   SHA256_M32_H10 = 0x06,
   SHA256_M32_H15 = 0x07,
   SHA256_M32_H20 = 0x08,
   SHA256_M32_H25 = 0x09,
 
   // --- draft-fluhrer-lms-more-parm-sets-11 ---
   // SHA-256/192 based
   SHA256_M24_H5 = 0x0a,
   SHA256_M24_H10 = 0x0b,
   SHA256_M24_H15 = 0x0c,
   SHA256_M24_H20 = 0x0d,
   SHA256_M24_H25 = 0x0e,
 
   // SHAKE-256/256 based
   SHAKE_M32_H5 = 0x0f,
   SHAKE_M32_H10 = 0x10,
   SHAKE_M32_H15 = 0x11,
   SHAKE_M32_H20 = 0x12,
   SHAKE_M32_H25 = 0x13,
 
   // SHAKE-256/192 based
   SHAKE_M24_H5 = 0x14,
   SHAKE_M24_H10 = 0x15,
   SHAKE_M24_H15 = 0x16,
   SHAKE_M24_H20 = 0x17,
   SHAKE_M24_H25 = 0x18

-- NOTE: Deprecated
BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2, BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE
- alg_name: "SPHINCS+"
- params: SphincsParameters, default: SphincsPlus-SHA2-128s-r3.1

data SphincsHash
    = SphincsSHA256
    | SphincsSHAKE256
    | SphincsHaraka

data SphincsParameterSet
   = Sphincs128Small
   | Sphincs128Fast
   | Sphincs192Small
   | Sphincs192Fast
   | Sphincs256Small
   | Sphincs256Fast
 
   | SLHDSA128Small
   | SLHDSA128Fast
   | SLHDSA192Small
   | SLHDSA192Fast
   | SLHDSA256Small
   | SLHDSA256Fast

data SphincsParams = MkSphincsParams SphincsHash SphincsParameterSet

-- NOTE: Mostly an alias for SPHINCSPlus
-- Diferences are: No Haraka support, added prehash mode
BOTAN_HAS_SLH_DSA_WITH_SHA2, BOTAN_HAS_SLH_DSA_WITH_SHAKE
- alg_name: "SLH-DSA"
- params: SLH_DSA_Parameters, default:  SLH-DSA-SHA2-128s

BOTAN_HAS_XMSS_RFC8391
- alg_name: "XMSS"
- params: XMSS_Parameters, default: XMSS-SHA2-10-512

data XMSSHash
    = XMSSSHA256
    | XMSSSHAKE256

data XMSSTreeHeight
    = XMSSTreeHeight10
    | XMSSTreeHeight16
    | XMSSTreeHeight20

data XMSSStrength
    = XMSSStrength192
    | XMSSStrength256
    | XMSSStrength512

data XMSSParameters
    = MkXMSSParameters XMSSHash XMSSTreeHeight XMSSStrength

-- OR AS AN ENUM
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

BOTAN_HAS_ED25519
- alg_name: "Ed25519"
- params: none
- return: Ed25519_PrivateKey

BOTAN_HAS_ED448
- alg_name: "Ed448"
- params: none
- return: Ed448_PrivateKey

-- ECC crypto
-- NOTE: "SM2_Sig" or "SM2_Enc" are synonyms for "SM2"
-- NOTE: GOST might need to be more specific wrt 256 vs 512 but is deprecated so eh
BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO
- alg_name: "ECDSA" or "ECDH" or "ECKCDSA" or "ECGDSA" or "SM2" or "SM2_Sig" or "SM2_Enc" or "GOST-34.10" or "GOST-34.10-2012-256" or "GOST-34.10-2012-512"
- params: ECGroup, default: SM2 -> sm2p256v1, GOST-34.10 -> gost_256A, ECGDSA -> Brainpool256r1, otherwise secp256r1
- return: <ALG>_PrivateKey


-- DL crypto
BOTAN_HAS_DL_GROUP, BOTAN_HAS_DIFFIE_HELLMAN, BOTAN_HAS_DSA, BOTAN_HAS_ELGAMAL
- alg_name: "DH" or "DSA" or "ElGamal"
- params: DLGroup, default: DSA -> dsa/botan/2048, otherwise modp/ietf/2048
- return: <ALG>_PrivateKey

-}



{-
EME / PKEncryptParams
-}

data EME
    = EME_RAW
    | EME_PKCS1_v1_5
    | EME_OAEP HashType
    -- | EME_OAEP_MGF HashType Int
    | EME_HASH HashType
    | EME_SM2EncParam HashType

emeName :: EME -> ByteString
emeName EME_RAW = BOTAN_EME_RAW
emeName EME_PKCS1_v1_5 = BOTAN_EME_PKCS1_v1_5
emeName (EME_OAEP h) = BOTAN_EME_OAEP /$ hashName h
-- emeName (EME_OAEP_MGF h m) = EME_OAEP /$ commas
--     [ hashName h
--     , mgfName m
--     ]
emeName (EME_HASH h) = hashName h
emeName (EME_SM2EncParam h) = hashName h

{-
EMSA / PKSignParams
-}

data EMSA
    = EMSA_NONE
    -- | EMSA_RSA
    | EMSA4 HashType
    | EMSA_Ed25519Pure
    | EMSA_Ed25519Prehashed
    | EMSA_Ed25519GnuPG HashType
    | EMSA_HASH HashType
    | EMSA_SM2SignParam ByteString HashType
    -- | EMSA_XMSS
    -- | EMSA_Dilithium

-- TODO: Botan should have emsa constants somewhere
emsaName :: EMSA -> ByteString
emsaName EMSA_NONE = ""
emsaName (EMSA_HASH h) = hashName h
emsaName EMSA_Ed25519Pure = "Pure"
emsaName EMSA_Ed25519Prehashed = "Ed25519ph"
emsaName (EMSA4 h) = "EMSA4" /$ hashName h
emsaName (EMSA_Ed25519GnuPG h) = hashName h
emsaName (EMSA_SM2SignParam uid h) = commas [ uid, hashName h ]



{-
ALG             KA      KEM     Sign    Encrypt PQ      Notes
- Prime factorization
RSA             Yes     Yes     Yes     Yes
- DL Groups
DH              Yes
DSA                             Yes
ELGAMAL                                 Yes
- ECC
ECDH            Yes
EC*DSA                          Yes
ECIES                                   Yes             Not FFI supported
SM2             Yes     Yes     Yes     Yes
GOST-34.10                      Yes                     Deprecated
- Named curves
X25519          Yes
X448            Yes
ED25519                         Yes
ED448                           Yes
- Post-quantum
MCELIECE                Yes                     Yes
FRODOKEM                Yes                     Yes
KYBER                   Yes                     Yes
ML_KEM                  Yes                     Yes
DILITHIUM                       Yes             Yes
ML_DSA                          Yes             Yes
SPHINCS_PLUS                    Yes             Yes
SLH_DSA                         Yes             Yes
HSS_LMS                         Yes             Yes     Stateful
XMSS                            Yes             Yes     Stateful
-}

