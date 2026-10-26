{-# LANGUAGE OverloadedStrings #-}

module Botan.Hash
(   Hash(..)
,   HashDigest
,   withHash
,   hashInit
,   hashGetName
,   hashGetBlockSize
,   hashGetDigestSize
,   hashCopyState
,   hashUpdate
,   hashFinalize
,   hashClear
,   hashUpdateFinalize
,   hashUpdateFinalizeClear
,   hash
,   HashType(..)
,   BLAKE2bSize
,   blake2b
,   Keccak1600Size
,   keccak1600
,   SHA3Size
,   sha3
,   SHAKE128Size
,   shake128
,   SHAKE256Size
,   shake256
,   Skein512Size
,   skein512
,   Skein512Salt
,   hashName
,   hashDigestSize
,   hashBlockSize
,   generateHashTypeDigestSizes
,   generateHashTypeBlockSizes
,   hashes
,   isCryptoHash
,   isChecksum
,   cryptoHashes
) where

import Botan.Bindings.Hash
import Botan.Internal.Prelude

import qualified Data.ByteString as ByteString

{-
Bindings Memorized instance
-}

instance Memorized BotanHash where
    type Memo BotanHash = Ptr
    type MemRep BotanHash = BotanHashStruct
    withMemo (MkBotanHash ptr) action = action ptr

{-
Hash object
-}

newtype Hash = MkHash { foreignPtr :: ForeignPtr BotanHashStruct }

instance Memorized Hash where
    type Memo Hash = ForeignPtr
    type MemRep Hash = BotanHashStruct
    withMemo (MkHash fptr) action = action fptr

instance BotanObject Hash where

    type BotanStruct Hash = BotanHashStruct
    type BotanPtr    Hash = BotanHash

    toBotanPtr = MkBotanHash
    toBotan    = MkHash
    botanFinalizer  = botan_hash_destroy

{--
Hash functions
--}

withHash :: Hash -> (BotanHash -> IO a) -> IO a
withHash = withBotanPtr @Hash

-- TODO: Push ByteString.useAsCString out to a Memory helper using WithPtr
hashInit :: HashType -> IO Hash
hashInit htype = ByteString.useAsCString (hashName htype) $ \ htypePtr -> do
    createBotan @Hash $ \ outPtr -> botan_hash_init outPtr (ConstPtr htypePtr) 0

hashGetName :: Hash -> IO ByteString
hashGetName = botanObjectName botan_hash_name

hashCopyState :: Hash -> IO Hash
hashCopyState source = withHash source $ \ sourcePtr -> do
    createBotan @Hash $ \ outPtr -> botan_hash_copy_state outPtr sourcePtr

hashClear :: Hash -> IO ()
hashClear h = withHash h $ \ botanHash -> do
    throwBotanIfNegative_ $ botan_hash_clear botanHash

-- TODO: Generalize this in Memory somewhere as:
--     allocaPeek :: Int -> (Ptr a -> IO ()) -> IO a
hashGetBlockSize :: Hash -> IO Int
hashGetBlockSize h = mask_ $ alloca $ \ szPtr -> do
    withHash h $ \ botanHash -> do
        throwBotanIfNegative_ $ botan_hash_block_size botanHash szPtr
        fromIntegral <$> peek szPtr

-- NOTE: Formerly hashOutputLength
hashGetDigestSize :: Hash -> IO Int
hashGetDigestSize h = mask_ $ alloca $ \ szPtr -> do
    withHash h $ \ botanHash -> do
        throwBotanIfNegative_ $ botan_hash_output_length botanHash szPtr
        fromIntegral <$> peek szPtr

hashUpdate :: Hash -> ByteString -> IO ()
hashUpdate h bs = withHash h $ \ hPtr -> do
    withPtr bs $ \ bsPtr -> do
        throwBotanIfNegative_ $ botan_hash_update hPtr (ConstPtr bsPtr) (fromIntegral $ ByteString.length bs)

type HashDigest = ByteString

hashFinalize :: Hash -> IO HashDigest
hashFinalize h = withHash h $ \ hPtr -> do
    sz <- hashGetDigestSize h
    allocInit ByteStringAllocator sz $ \ fPtr -> withPtr fPtr $ \ digestPtr -> do
        throwBotanIfNegative_ $ botan_hash_final hPtr digestPtr

-- TODO:
-- pkcsHashId
--     :: ByteString       -- ^ __hash_name__
--     -> IO ByteString    -- ^ __pkcs_id[]__
-- pkcsHashId = undefined


-- Convenience

hashUpdateFinalize :: Hash -> ByteString -> IO HashDigest
hashUpdateFinalize ctx bytes = do
    hashUpdate ctx bytes
    hashFinalize ctx

hashUpdateFinalizeClear :: Hash -> ByteString -> IO HashDigest
hashUpdateFinalizeClear ctx bytes = do
    dg <- hashUpdateFinalize ctx bytes
    hashClear ctx
    return dg
-- Or: hashUpdateFinalize ctx bytes <* hashClear ctx

hash :: HashType -> ByteString -> IO HashDigest
hash htype msg = do
    h <- hashInit htype
    hashUpdateFinalize h msg


{-
Hash algorithms
-}

data HashType
    = BLAKE2b BLAKE2bSize
    | GOST_34_11
    | Keccak1600 Keccak1600Size
    | MD4
    | MD5
    | RIPEMD160
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512
    | SHA512_256
    | SHA3 SHA3Size
    | SHAKE128 SHAKE128Size
    | SHAKE256 SHAKE256Size
    | SM3
    | Skein512 Skein512Size Skein512Salt
    | Streebog256
    | Streebog512
    | Whirlpool
    -- Combination strategies
    | Parallel HashType HashType
    | Comb4P HashType HashType
    -- Checksums
    | Adler32
    | CRC24
    | CRC32
    deriving stock (Eq, Ord, Show)

-- TODO: This needs *much better handling* than just throwing errors willy-nilly
-- They shouldn't produce errors if the constructor functions are used though

-- 1-64 bytes, eg: 8-512 in multiples of 8
type BLAKE2bSize = Int  

blake2b :: BLAKE2bSize -> HashType
blake2b sz
    | sz >= 8 && sz <= 512 && sz `mod` 8 == 0 = BLAKE2b sz
    | otherwise = error "Invalid BLAKE2b variant"

-- 224, 256, 384, 512
type Keccak1600Size = Int

keccak1600 :: Keccak1600Size -> HashType
keccak1600 n
    | n `elem` [224, 256, 384, 512] = Keccak1600 n
    | otherwise = error "Invalid Keccak-1600 variant"

-- 224, 256, 384, 512
type SHA3Size = Int

sha3 :: SHA3Size -> HashType
sha3 n
    | n `elem` [224, 256, 384, 512] = SHA3 n
    | otherwise = error "Invalid SHA-3 variant"

type SHAKE128Size = Int

shake128 :: SHAKE128Size -> HashType
shake128 sz = SHAKE128 sz

type SHAKE256Size = Int

shake256 :: SHAKE256Size -> HashType
shake256 sz = SHAKE256 sz

type Skein512Size = Int
type Skein512Salt = ByteString  -- Must not contain ")", can contain "," if escaped, best use ASCII text

skein512 :: Skein512Size -> Skein512Salt -> HashType
skein512 sz salt = Skein512 sz salt

hashName :: HashType -> ByteString
hashName (BLAKE2b sz) = BOTAN_HASH_BLAKE2B /$ prn sz
hashName (Keccak1600 sz) = BOTAN_HASH_KECCAK_1600 /$ prn sz
hashName GOST_34_11   = BOTAN_HASH_GOST_34_11
hashName MD4 = BOTAN_HASH_MD4
hashName MD5 = BOTAN_HASH_MD5
hashName RIPEMD160 = BOTAN_HASH_RIPEMD_160
hashName SHA1 = BOTAN_HASH_SHA1
hashName SHA224 = BOTAN_HASH_SHA_224
hashName SHA256 = BOTAN_HASH_SHA_256
hashName SHA384 = BOTAN_HASH_SHA_384
hashName SHA512 = BOTAN_HASH_SHA_512
hashName SHA512_256 = BOTAN_HASH_SHA_512_256
hashName (SHA3 sz) = BOTAN_HASH_SHA_3 /$ prn sz
hashName (SHAKE128 sz) = BOTAN_HASH_SHAKE_128 /$ prn sz
hashName (SHAKE256 sz) = BOTAN_HASH_SHAKE_256 /$ prn sz
hashName SM3 = BOTAN_HASH_SM3
hashName (Skein512 sz salt) = BOTAN_HASH_SKEIN_512 /$ commas [ prn sz, salt ]
hashName Streebog256 = BOTAN_HASH_STREEBOG_256
hashName Streebog512 = BOTAN_HASH_STREEBOG_512
hashName Whirlpool = BOTAN_HASH_WHIRLPOOL
hashName (Parallel a b) = BOTAN_HASH_STRAT_PARALLEL /$ commas
    [ hashName a
    , hashName b
    ]
hashName (Comb4P a b) = BOTAN_HASH_STRAT_COMB4P /$ commas
    [ hashName a
    , hashName b
    ]
hashName Adler32 = BOTAN_CHECKSUM_ADLER32
hashName CRC24 = BOTAN_CHECKSUM_CRC24
hashName CRC32 = BOTAN_CHECKSUM_CRC32

{- |
Statically-calculated digest size in bytes
-}
hashDigestSize :: HashType -> Int
hashDigestSize (BLAKE2b n) | n >= 8 && n <= 512 && n `mod` 8 == 0
                                    = div n 8
hashDigestSize (BLAKE2b _)      = error "hashDigestSize: Invalid BLAKE2b variant"
hashDigestSize GOST_34_11       = 32
hashDigestSize (Keccak1600 224) = 28
hashDigestSize (Keccak1600 256) = 32
hashDigestSize (Keccak1600 384) = 48
hashDigestSize (Keccak1600 512) = 64
hashDigestSize (Keccak1600 _)   = error "hashDigestSize: Invalid Keccak-1600 variant"
hashDigestSize MD4              = 16
hashDigestSize MD5              = 16
hashDigestSize RIPEMD160        = 20
hashDigestSize SHA1             = 20
hashDigestSize SHA224           = 28
hashDigestSize SHA256           = 32
hashDigestSize SHA384           = 48
hashDigestSize SHA512           = 64
hashDigestSize SHA512_256       = 32
hashDigestSize (SHA3 224)       = 28
hashDigestSize (SHA3 256)       = 32
hashDigestSize (SHA3 384)       = 48
hashDigestSize (SHA3 512)       = 64
hashDigestSize (SHA3 _)         = error "hashDigestSize: Invalid SHA-3 variant"
hashDigestSize (SHAKE128 n)     = div n 8
hashDigestSize (SHAKE256 n)     = div n 8
hashDigestSize SM3              = 32
hashDigestSize (Skein512 n _)   = div n 8
hashDigestSize Streebog256      = 32
hashDigestSize Streebog512      = 64
hashDigestSize Whirlpool        = 64
hashDigestSize Adler32          = 4
hashDigestSize CRC24            = 3
hashDigestSize CRC32            = 4
hashDigestSize (Parallel ha hb) = error "Unimplemented: hashDigestSize"
hashDigestSize (Comb4P ha hb)   = error "Unimplemented: hashDigestSize"
{-# WARNING hashDigestSize "Unimplemented for: Parallel, Comb4P" #-}

generateHashTypeDigestSizes :: [HashType] -> IO ()
generateHashTypeDigestSizes hashes = do
    each <- forM hashes  $ \ htype -> do
        h <- hashInit htype
        dsz <- hashGetDigestSize h
        return $ concat
            [ "hashDigestSize "
            , showsPrec 11 htype ""
            , " = "
            , show dsz
            ]
    putStrLn $ unlines $
        "hashDigestSize :: HashType -> Int"
        : each


{- |
Statically-calculated block size in bytes
-}
hashBlockSize :: HashType -> Int
hashBlockSize (BLAKE2b _)      = 128
hashBlockSize GOST_34_11       = 32
hashBlockSize (Keccak1600 224) = 144
hashBlockSize (Keccak1600 256) = 136
hashBlockSize (Keccak1600 384) = 104
hashBlockSize (Keccak1600 512) = 72
hashBlockSize (Keccak1600 _)   = error "hashBlockSize: Invalid Keccak-1600 variant"
hashBlockSize MD4              = 64
hashBlockSize MD5              = 64
hashBlockSize RIPEMD160        = 64
hashBlockSize SHA1             = 64
hashBlockSize SHA224           = 64
hashBlockSize SHA256           = 64
hashBlockSize SHA384           = 128
hashBlockSize SHA512           = 128
hashBlockSize SHA512_256       = 128
hashBlockSize (SHA3 224)       = 144
hashBlockSize (SHA3 256)       = 136
hashBlockSize (SHA3 384)       = 104
hashBlockSize (SHA3 512)       = 72
hashBlockSize (SHA3 _)         = error "hashBlockSize: Invalid SHA-3 variant"
hashBlockSize (SHAKE128 _)     = 168
hashBlockSize (SHAKE256 _)     = 136
hashBlockSize SM3              = 64
hashBlockSize (Skein512 _ _)   = 64
hashBlockSize Streebog256      = 64
hashBlockSize Streebog512      = 64
hashBlockSize Whirlpool        = 64
hashBlockSize Adler32          = error "Unimplemented: checksumBlockSize"
hashBlockSize CRC24            = error "Unimplemented: checksumBlockSize"
hashBlockSize CRC32            = error "Unimplemented: checksumBlockSize"
hashBlockSize (Parallel ha hb) = error "Unimplemented: hashBlockSize"
hashBlockSize (Comb4P ha hb)   = error "Unimplemented: hashBlockSize"
{-# WARNING hashBlockSize "Unimplemented for: Adler32, CRC24, CRC32, Parallel, Comb4P" #-}

generateHashTypeBlockSizes :: [HashType] -> IO ()
generateHashTypeBlockSizes hashes = do
    each <- forM hashes  $ \ htype -> do
        h <- hashInit htype
        bsz <- hashGetBlockSize h
        return $ concat
            [ "hashBlockSize "
            , showsPrec 11 htype ""
            , " = "
            , show bsz
            ]
    putStrLn $ unlines $
        "hashBlockSize :: HashType -> Int"
        : each


hashes :: [ HashType ]
hashes =
    [ BLAKE2b 256
    , GOST_34_11
    , Keccak1600 224
    , Keccak1600 256
    , Keccak1600 384
    , Keccak1600 512
    , MD4
    , MD5
    , RIPEMD160
    , SHA1
    , SHA224
    , SHA256
    , SHA384
    , SHA512
    , SHA512_256
    , SHA3 224
    , SHA3 256
    , SHA3 384
    , SHA3 512
    , SHAKE128 128
    , SHAKE256 256
    , SM3
    , Skein512 512 ""
    , Streebog256
    , Streebog512
    , Whirlpool
    , Adler32
    , CRC24
    , CRC32
    ]

isChecksum :: HashType -> Bool
isChecksum Adler32 = True
isChecksum CRC24   = True
isChecksum CRC32   = True
-- NOTE: I'm not sure using Parallel / Comb4P with checksums is supported
isChecksum (Parallel a b) = isChecksum a && isChecksum b
isChecksum (Comb4P a b)   = isChecksum a && isChecksum b
isChecksum _              = False

isCryptoHash :: HashType -> Bool
isCryptoHash Adler32 = False
isCryptoHash CRC24   = False
isCryptoHash CRC32   = False
isCryptoHash (Parallel a b) = isCryptoHash a && isCryptoHash b
isCryptoHash (Comb4P a b)   = isCryptoHash a && isCryptoHash b
isCryptoHash _              = True

cryptoHashes :: [HashType]
cryptoHashes = filter isCryptoHash hashes

checksums :: [HashType]
checksums = filter isChecksum hashes