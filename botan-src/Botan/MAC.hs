{-# LANGUAGE OverloadedStrings #-}

module Botan.MAC
(   mac
,   verifyMAC
,   nmac
,   verifyNMAC
,   MACKey(..)
,   MACNonce(..)
,   MACDigest(..)
,   generateMACKey
,   generatePreferredMACKey
,   macPreferredKeySize
,   macGenerateNonce
,   generatePreferredMACNonce
,   macNonceLengthIsValid
,   MACType(..)
,   macName
,   macKeySpec
,   macDigestSize
,   isNoncedMAC
,   MAC(..)
,   withMAC
,   macInit
,   macGetName
,   macGetDigestSize
,   macGetKeyspec
,   macSetKey
,   macSetNonce
,   macUpdate
,   macFinalize
,   macClear
,   generateMACKeySpecs
,   generateMACDigestSizes
,   macs
) where

import Botan.Internal.Prelude
import Botan.BlockCipher
import Botan.Hash
import Botan.Bindings.MAC
import Botan.RNG

import qualified Data.ByteString as ByteString

-- TODO: Consider cipherNonceSize(IsValid) vs cipherNonceSpec

-- Main interface

mac :: MACType -> MACKey -> ByteString -> MACDigest
mac ty k bs = doIO $ _mac ty k Nothing bs

verifyMAC ::  MACType -> MACKey -> ByteString -> MACDigest -> Bool
verifyMAC ty k bs dg = doIO $ _verifyMAC ty k Nothing bs dg

nmac :: MACType -> MACKey -> MACNonce -> ByteString -> MACDigest
nmac ty k n bs = doIO $ _mac ty k (Just n) bs

verifyNMAC ::  MACType -> MACKey -> MACNonce -> ByteString -> MACDigest -> Bool
verifyNMAC ty k n bs dg = doIO $ _verifyMAC ty k (Just n) bs dg

-- TODO:
-- easyNMAC :: MACType -> MACKey -> ByteString -> IO (MACDigest, MACNonce)

_mac :: MACType -> MACKey -> Maybe MACNonce -> ByteString -> IO MACDigest
_mac macType key nonce input = do
    m <- macInit macType
    macSetKey m key.bytes
    case nonce of
        Just n -> macSetNonce m n.bytes
        _ -> pure ()
    macUpdate m input
    macFinalize m

_verifyMAC :: MACType -> MACKey -> Maybe MACNonce -> ByteString -> MACDigest -> IO Bool
_verifyMAC macType key nonce input dg = do
    dg' <- _mac macType key nonce input
    return $ dg' == dg


-- Data types

newtype MACKey = MkMACKey { bytes :: ByteString }
    deriving newtype (Eq, Show)

generateMACKey :: MACType -> Int -> IO (Maybe MACKey)
generateMACKey macType sz | validSize (macKeySpec macType) sz
    = Just . MkMACKey <$> userThreadsafeRNGGet sz
generateMACKey _ _ = pure Nothing

generatePreferredMACKey :: MACType -> IO MACKey
generatePreferredMACKey macType = MkMACKey <$> userThreadsafeRNGGet (macPreferredKeySize macType)

macPreferredKeySize :: MACType -> Int
macPreferredKeySize (CMAC bc)     = blockCipherPreferredKeySize bc
macPreferredKeySize (GMAC bc)     = blockCipherPreferredKeySize bc
macPreferredKeySize (HMAC h)      = hashDigestSize h
macPreferredKeySize Poly1305      = 32
macPreferredKeySize (SipHash _ _) = 16
macPreferredKeySize X9_19_MAC     = 16

newtype MACNonce = MkMACNonce { bytes :: ByteString }
    deriving newtype (Eq, Show)

macGenerateNonce :: MACType -> Int -> IO (Maybe MACNonce)
macGenerateNonce macType sz | macNonceLengthIsValid macType sz = Just . MkMACNonce <$> userThreadsafeRNGGet sz
macGenerateNonce _ _ = pure Nothing

macPreferredNonceSize :: MACType -> Maybe Int
macPreferredNonceSize (GMAC _) = Just 12
macPreferredNonceSize _ = Nothing

generatePreferredMACNonce :: MACType -> IO (Maybe MACNonce)
generatePreferredMACNonce macType = case macPreferredNonceSize macType of
    Just sz -> Just . MkMACNonce <$> userThreadsafeRNGGet sz
    _       -> pure Nothing

macNonceLengthIsValid :: MACType -> Int -> Bool
macNonceLengthIsValid (GMAC _) n | 0 <= n && n <= 1024 = True
macNonceLengthIsValid _        _                       = False
-- NOTE: What about HMAC? Can it take a nonce?

-- macDefaultNonceLength :: MACType -> Maybe Int
-- macDefaultNonceLength (GMAC _) = Just 12
-- macDefaultNonceLength _ = Nothing

-- TODO: Rename MACTag?
newtype MACDigest = MkMACDigest { bytes :: ByteString }
    deriving newtype (Eq, Show)


-- Algorithm type

data MACType
    = CMAC BlockCipherType
    | GMAC BlockCipherType
    -- | CBC_MAC BlockCipherType
    | HMAC HashType
    -- | KMAC_128 BlockCipherType
    -- | KMAC_256 BlockCipherType
    | Poly1305
    | SipHash Int Int
    | X9_19_MAC
    deriving stock (Eq, Ord, Show)

macName :: MACType -> ByteString
macName (CMAC bc) = BOTAN_MAC_CMAC /$ blockCipherName bc   
macName (GMAC bc) = BOTAN_MAC_GMAC /$ blockCipherName bc
-- macName (CBC_MAC bc) = BOTAN_MAC_CBC_MAC /$ blockCipherName bc
macName (HMAC h) = BOTAN_MAC_HMAC /$ hashName h
-- macName (KMAC_128 bc) = BOTAN_MAC_KMAC_128 /$ blockCipherName bc
-- macName (KMAC_256 bc) = BOTAN_MAC_KMAC_256 /$ blockCipherName bc
macName Poly1305 = BOTAN_MAC_Poly1305
macName (SipHash ir fr) = BOTAN_MAC_SipHash /$ commas [ prn ir, prn fr ]
macName X9_19_MAC = BOTAN_MAC_X9_19_MAC


macKeySpec :: MACType -> SizeSpec MACKey
macKeySpec (CMAC bc)     = coerceSizeSpec $ blockCipherKeySpec bc
macKeySpec (GMAC bc)     = coerceSizeSpec $ blockCipherKeySpec bc
macKeySpec (HMAC _h)     = sizeSpec 0 4096 1
macKeySpec Poly1305      = sizeSpec 32 32 1
macKeySpec (SipHash _ _) = sizeSpec 16 16 1
macKeySpec X9_19_MAC     = sizeSpec 8 16 8

-- NOTE: Size in bytes
macDigestSize :: MACType -> Int
macDigestSize (CMAC bc)     = blockCipherBlockSize bc
macDigestSize (GMAC _)      = 16    -- Always 16
macDigestSize (HMAC h)      = hashDigestSize h
macDigestSize Poly1305      = 16
macDigestSize (SipHash _ _) = 8
macDigestSize X9_19_MAC     = 8

-- NOTE: Botan does not have a MAC nonce size query, but only GMAC requires a
-- nonce, and it accepts a nonce of any length

isNoncedMAC :: MACType -> Bool
isNoncedMAC (GMAC _) = True
isNoncedMAC _ = False

-- Algorithms

-- Bindings instance

instance Memorized BotanMAC where
    type Memo BotanMAC = Ptr
    type MemRep BotanMAC = BotanMACStruct
    withMemo (MkBotanMAC ptr) action = action ptr

-- Context object

newtype MAC = MkMAC { foreignPtr :: ForeignPtr BotanMACStruct }

instance Memorized MAC where
    type Memo MAC = ForeignPtr
    type MemRep MAC = BotanMACStruct
    withMemo (MkMAC fptr) action = action fptr

instance BotanObject MAC where

    type BotanStruct MAC = BotanMACStruct
    type BotanPtr    MAC = BotanMAC

    toBotanPtr = MkBotanMAC
    toBotan    = MkMAC
    botanFinalizer  = botan_mac_destroy

-- Bindings / IO interface

withMAC :: MAC -> (BotanMAC -> IO a) -> IO a
withMAC = withBotanPtr @MAC

-- | Initialize a message authentication code object
macInit
    :: MACType  -- ^ __mac_name__: name of the hash function, e.g., "HMAC(SHA-384)"
    -> IO MAC   -- ^ __mac__: mac object
-- macInit = mkCreateObjectCString createMAC (\ out name -> botan_mac_init out name 0)
macInit macType = useAsCString (macName macType) $ \ namePtr -> do
    createBotan @MAC $ \ outPtr -> botan_mac_init outPtr (ConstPtr namePtr) 0

-- | Writes the output length of the message authentication code to *output_length
macGetDigestSize
    :: MAC      -- ^ __mac__: mac object
    -> IO Int   -- ^ __output_length__: output buffer to hold the MAC output length
-- macOutputLength = mkGetSize withMAC botan_mac_output_length
macGetDigestSize = botanObjectIntegral botan_mac_output_length

-- | Sets the key on the MAC
macSetKey
    :: MAC          -- ^ __mac__: mac object
    -> ByteString   -- ^ __key__: buffer holding the key
    -> IO ()
-- macSetKey = mkWithObjectSetterCBytesLen withMAC botan_mac_set_key
-- NOTE: This is the same as cipherSetKey, candidate for convenience function
macSetKey mac key = mask_ $ withMAC mac $ \ macPtr -> do
    withPtr key $ \ keyPtr -> do
        throwBotanIfNegative_ $ botan_mac_set_key macPtr
            (ConstPtr keyPtr)
            (fromIntegral (ByteString.length key))


-- NOTE: Not all MACs require a nonce
--  Eg, GMAC requires a nonce
--  Other MACs do not require a nonce, and will cause a BadParameterException (-32)
-- | Sets the nonce on the MAC
macSetNonce
    :: MAC          -- ^ __mac__: mac object
    -> ByteString   -- ^ __nonce__: buffer holding the nonce
    -> IO ()
-- macSetNonce = mkWithObjectSetterCBytesLen withMAC botan_mac_set_nonce
-- NOTE: This is the same as cipherSetKey, candidate for convenience function
macSetNonce mac nonce = mask_ $ withMAC mac $ \ macPtr -> do
    withPtr nonce $ \ noncePtr -> do
        throwBotanIfNegative_ $ botan_mac_set_nonce macPtr
            (ConstPtr noncePtr)
            (fromIntegral (ByteString.length nonce))

-- | Send more input to the message authentication code
macUpdate
    :: MAC          -- ^ __mac__: mac object
    -> ByteString   -- ^ __buf__: input buffer
    -> IO ()
-- macUpdate = mkWithObjectSetterCBytesLen withMAC botan_mac_update
-- NOTE: This is the same as cipherSetKey, candidate for convenience function
-- macUpdate mac input = mask_ $ withMAC mac $ \ macPtr -> do
--     withPtr input $ \ inputPtr -> do
--         throwBotanIfNegative_ $ botan_mac_update macPtr
--             (ConstPtr inputPtr)
--             (fromIntegral (ByteString.length input))
-- NOTE: We can simply by using withPtrLen, still the same function
macUpdate mac input =
    mask_ $ withMAC mac $ \ macPtr ->
    withPtrLen input $ \ inputPtr inputSz ->
    throwBotanIfNegative_ $ botan_mac_update macPtr
        (ConstPtr inputPtr)
        (fromIntegral inputSz)

-- TODO: Digest type
{- |
Finalizes the MAC computation and writes the output to
out[0:botan_mac_output_length()] then reinitializes for computing
another MAC as if botan_mac_clear had been called.
-}
macFinalize
    :: MAC          -- ^ __mac__: mac object
    -> IO MACDigest -- ^ __out[]__: output buffer
macFinalize mac = withMAC mac $ \ macPtr -> do
    sz <- macGetDigestSize mac
    bs <- allocInit ByteStringAllocator sz $ \ fPtr -> withPtr fPtr $ \ bytesPtr ->
        throwBotanIfNegative_ $ botan_mac_final macPtr bytesPtr
    pure $ MkMACDigest bs

{- |
Reinitializes the state of the MAC computation. A MAC can
be computed (with update/final) immediately.
-}
macClear
    :: MAC -- @mac@: mac object
    -> IO ()
-- macClear = mkAction withMAC botan_mac_clear
macClear mac = mask_ $ withMAC mac $ \ macPtr -> do
    throwBotanIfNegative_ $ botan_mac_clear macPtr

-- | Get the name of this MAC
macGetName
    :: MAC              -- ^ __mac__: the object to read
    -> IO ByteString    -- ^ __name__: output buffer
-- macName = mkGetCString withMAC botan_mac_name
macGetName = botanObjectName botan_mac_name

-- | Get the key length limits of this auth code
-- macGetKeyspec
--     :: MAC              -- ^ __mac__: the object to read
--     -> IO (Int,Int,Int) -- ^ __(min,max,mod)__: minimum maximum and modulo keylength of MAC
-- macGetKeyspec = mkGetSizes3 withMAC botan_mac_get_keyspec
-- NOTE: Difference in function signature
macGetKeyspec :: MAC -> IO (SizeSpec MACKey)
macGetKeyspec = botanObjectKeyspec botan_mac_get_keyspec

-- Custom convenience

-- Helpers for generating

generateMACKeySpecs :: IO ()
generateMACKeySpecs = do
    each <- forM macs $ \ m -> do
        ctx <- macInit m
        spec <- macGetKeyspec ctx
        return $ concat $
            [ "macKeySpec "
            , showsPrec 11 m ""
            , " = "
            , showsPrec 11 spec ""
            ]
    putStrLn $ unlines $
        "macKeySpec :: MACType -> SizeSpec MACKey"
        : each

generateMACDigestSizes :: IO ()
generateMACDigestSizes = do
    each <- forM macs $ \ m -> do
        ctx <- macInit m
        dsz <- macGetDigestSize ctx
        return $ concat $
            [ "macDigestSize "
            , showsPrec 11 m ""
            , " = "
            , show dsz
            ]
    putStrLn $ unlines $
        "macDigestSize :: MACType -> Int"
        : each


macs :: [ MACType ]
macs = concat
    [ [ CMAC bc | bc <- blockCiphers ]
    , [ GMAC bc | bc <- blockCiphers ] -- Requires a nonce
    , [ HMAC h  | h  <- cryptoHashes ]
    , [ Poly1305 ]
    , [ SipHash c d | c <- [ 1 .. 4 ], d <- [ 2 .. 8 ] ]
    , [ X9_19_MAC ]
    ]

{-
import Botan.Hash
import Botan.MAC
:set -XOverloadedStrings
m = HMAC SHA512
k <- generatePreferredMACKey m
n <- generatePreferredMACNonce m
msg = "Fee fi fo fum!" :: ByteString
tag <- mac m k n msg
auth m k n msg tag
-- True

-}
