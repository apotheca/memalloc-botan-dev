{-# LANGUAGE OverloadedStrings #-}

module Botan.BlockCipher
(   BlockCipher(..)
,   BlockCipherKey
,   BlockCipherText
,   withBlockCipher
,   blockCipherInit
,   blockCipherClear
,   blockCipherSetKey
,   blockCipherGetName
,   blockCipherGetBlockSize
,   blockCipherGetKeyspec
,   blockCipherEncryptBlocks
,   blockCipherDecryptBlocks
,   blockEncrypt
,   blockDecrypt
,   BlockCipherType(..)
,   blockCipherName
,   blockCipherBlockSize
,   blockCipherKeySpec
,   BlockCipher128Type(..)
,   blockCipher128Type
,   isBlockCipher128Type
,   blockCiphers
,   blockCipher128s
,   nonBlockCipher128s
,   generateBlockCipherKey
,   blockCipherPreferredKeySize
,   generatePreferredBlockCipherKey
) where

import Botan.Internal.String
import Botan.Internal.Object -- TODO: Move to Botan.Internal.Object
import Botan.Internal.Error
import Botan.Hash
import Botan.KeySpec
import Botan.RNG

import Botan.Bindings.BlockCipher

import Botan.Internal.Prelude

import qualified Data.ByteString as ByteString

{-
Bindings Memorized instance
-}

instance Memorized BotanBlockCipher where
    type Memo BotanBlockCipher = Ptr
    type MemRep BotanBlockCipher = BotanBlockCipherStruct
    withMemo (MkBotanBlockCipher ptr) action = action ptr

{-
BlockCipher object
-}

-- TODO: Also attach the BlockCipherType to the BlockCipher?
-- Technically its recoverable via parsing blockCipherName, but that is
-- overkill compared to tagging it when we create it.
-- This does complicate the use of BotanObject, but we can establish and follow
-- a pattern and then apply it globally.
newtype BlockCipher = MkBlockCipher { foreignPtr :: ForeignPtr BotanBlockCipherStruct }

instance Memorized BlockCipher where
    type Memo BlockCipher = ForeignPtr
    type MemRep BlockCipher = BotanBlockCipherStruct
    withMemo (MkBlockCipher fptr) action = action fptr

instance BotanObject BlockCipher where

    type BotanStruct BlockCipher = BotanBlockCipherStruct
    type BotanPtr    BlockCipher = BotanBlockCipher

    toBotanPtr = MkBotanBlockCipher
    toBotan    = MkBlockCipher
    botanFinalizer  = botan_block_cipher_destroy

{-
Block cipher keys
-}

type BlockCipherKey = ByteString

-- data BlockCipherKey
--     = MkBlockCipherKey
--     { cipherType     :: BlockCipherType
--     , bytes :: ByteString
--     }

-- instance Memorized BlockCipherKey where
--     type Memo BlockCipherKey = ForeignPtr
--     type MemRep BlockCipherKey = Word8
--     withMemo (MkBlockCipherKey _ bs) = withForeignPtr bs

-- instance WithMemory ForeignPtr BlockCipherKey where
-- instance WithMemory Ptr BlockCipherKey where
--     withMemory (MkBlockCipherKey _ bs) = withPtr bs

-- instance HasSpec BlockCipherKey where
--     type Spec BlockCipherKey = SizeSpec BlockCipherKey
--     -- spec (MkBlockCipherKey ty _) = _

-- instance HasStrat BlockCipherKey where
--     type Strat BlockCipherKey = Int

-- instance HasSecretKey BlockCipher where
--     type SecretKey BlockCipher = BlockCipherKey
--     getSecretKeySpec = blockCipherKeyspec

{-
Block cipher functions
-}

withBlockCipher :: BlockCipher -> (BotanBlockCipher -> IO a) -> IO a
withBlockCipher = withBotanPtr @BlockCipher

blockCipherInit :: BlockCipherType -> IO BlockCipher
-- blockCipherInit = mkCreateObjectCString createBlockCipher botan_block_cipher_init
blockCipherInit bcType = useAsCString (blockCipherName bcType) $ \ namePtr -> do
    createBotan @BlockCipher $ \ outPtr -> botan_block_cipher_init outPtr (ConstPtr namePtr)

-- | Reinitializes a block cipher
--
-- You must call blockCipherSetKey in order to use the block cipher again.
blockCipherClear :: BlockCipher -> IO ()
blockCipherClear bc = withBlockCipher bc $ \ bcPtr -> do
    throwBotanIfNegative_ $ botan_block_cipher_clear bcPtr

-- | Set the key for a block cipher
--
-- Throws an error if the key is not valid.
blockCipherSetKey :: BlockCipher -> BlockCipherKey -> IO ()
blockCipherSetKey bc key = withBlockCipher bc $ \ bcPtr -> do
    withPtr key $ \ keyPtr -> do
        throwBotanIfNegative_ $ botan_block_cipher_set_key bcPtr
            (ConstPtr keyPtr)
            (fromIntegral (ByteString.length key))

-- | Return the block size of a block cipher.
blockCipherGetBlockSize :: BlockCipher -> IO Int
blockCipherGetBlockSize bc = withBlockCipher bc $ \ bcPtr -> do
    sz <- throwBotanIfNegative $ botan_block_cipher_block_size bcPtr
    return $ fromIntegral sz

-- | Get the name of a block cipher.
--
-- This function is not guaranteed to return the same exact value as used to initialize the context.
-- NOTE: Duplicated logic from hashName
blockCipherGetName :: BlockCipher -> IO ByteString
blockCipherGetName = botanObjectName botan_block_cipher_name

blockCipherGetKeyspec :: BlockCipher -> IO (SizeSpec BlockCipherKey)
-- blockCipherKeyspec bc = withBlockCipher bc $ \ bcPtr -> do
--     allocaMany @[CSize, CSize, CSize] $ \ (mn :> mx :> md :> PNil) -> do
--         throwBotanIfNegative_ $ botan_block_cipher_get_keyspec bcPtr mn mx md
--         mn' <- peek mn
--         mx' <- peek mx
--         md' <- peek md
--         return $ sizeSpec (fromIntegral mn') (fromIntegral mx') (fromIntegral md')
blockCipherGetKeyspec = botanObjectKeyspec botan_block_cipher_get_keyspec

-- TODO: newtype CipherText a = MkCipherText { unCipherText :: ByteString }
type BlockCipherText = ByteString

-- | Encrypt one or more blocks with a block cipher
--
-- Precondition: the length of the plaintext should be a multiple of the block
-- size, or this function throws an error.
blockCipherEncryptBlocks :: BlockCipher -> ByteString -> IO BlockCipherText
blockCipherEncryptBlocks blockCipher bytes = do
    blockSize <- blockCipherGetBlockSize blockCipher
    let (numBlocks,remBytes) = ByteString.length bytes `quotRem` blockSize
    when (remBytes /= 0) $
        error "blockCipherEncryptBlocks: length of the input plaintext is not a\
            \multiple of the block size"
    go (fromIntegral numBlocks)
    where
        go :: CSize -> IO BlockCipherText
        go numBlocks =
            withBlockCipher blockCipher $ \ blockCipherPtr ->
            withPtrLen bytes $ \ bytesPtr bytesLen ->
            -- NOTE: allocInit providing the ForeignPtr is correct, but tedious
            -- as it requires an extra withPtr
            allocInit ByteStringAllocator bytesLen $ \ fPtr ->
            withPtr fPtr $ \ destPtr ->
            throwBotanIfNegative_ $ botan_block_cipher_encrypt_blocks
                blockCipherPtr
                (ConstPtr bytesPtr)
                destPtr
                numBlocks

-- | Decrypt one or more blocks with a block cipher.
--
-- Precondition: the length of the ciphertext should be a multiple of the block size,
-- or this function throws an error.
--
-- If an incorrect key was set, the content of the decrypted plaintext is
-- unspecified.
blockCipherDecryptBlocks ::
     BlockCipher              -- ^ __bc__: The cipher object
  -> BlockCipherText    -- ^ __in[]__: The ciphertext
  -> IO ByteString            -- ^ __out[]__: The plaintext
blockCipherDecryptBlocks blockCipher bytes = do
    blockSize <- blockCipherGetBlockSize blockCipher
    let (numBlocks,remBytes) = ByteString.length bytes `quotRem` blockSize
    when (remBytes /= 0) $
        error "blockCipherDecryptBlocks: length of the input plaintext is not a\
            \multiple of the block size"
    go (fromIntegral numBlocks)
    where
        go :: CSize -> IO ByteString
        go numBlocks =
            withBlockCipher blockCipher $ \ blockCipherPtr ->
            withPtrLen bytes $ \ bytesPtr bytesLen ->
            -- NOTE: allocInit providing the ForeignPtr is correct, but tedious
            -- as it requires an extra withPtr
            allocInit ByteStringAllocator bytesLen $ \ fPtr ->
            withPtr fPtr $ \ destPtr ->
            throwBotanIfNegative_ $ botan_block_cipher_decrypt_blocks
                blockCipherPtr
                (ConstPtr bytesPtr)
                destPtr
                numBlocks

blockEncrypt :: BlockCipherType -> BlockCipherKey -> ByteString -> IO BlockCipherText
blockEncrypt bcType key msg = do
    bc <- blockCipherInit bcType
    blockCipherSetKey bc key
    blockCipherEncryptBlocks bc msg

blockDecrypt :: BlockCipherType -> BlockCipherKey -> BlockCipherText -> IO ByteString
blockDecrypt bcType key ct = do
    bc <- blockCipherInit bcType
    blockCipherSetKey bc key
    blockCipherDecryptBlocks bc ct

{-
BlockCipher algorithms
-}

data BlockCipherType
    = AES128
    | AES192
    | AES256
    | ARIA128
    | ARIA192
    | ARIA256
    | Blowfish
    | Camellia128
    | Camellia192
    | Camellia256
    | Cascade BlockCipherType BlockCipherType
    | CAST128
    | DES
    | TripleDES
    | GOST_28147_89
    | IDEA
    | Lion HashType ByteString (Maybe Word)
    | Noekeon
    | SEED
    | Serpent
    | SHACAL2
    | SM4
    | Threefish512
    | Twofish
    deriving stock (Eq, Ord, Show)

blockCipherName :: BlockCipherType -> ByteString
blockCipherName = bcname where

    bcname AES128        = BOTAN_BLOCK_CIPHER_AES_128
    bcname AES192        = BOTAN_BLOCK_CIPHER_AES_192
    bcname AES256        = BOTAN_BLOCK_CIPHER_AES_256
    bcname ARIA128       = BOTAN_BLOCK_CIPHER_ARIA_128
    bcname ARIA192       = BOTAN_BLOCK_CIPHER_ARIA_192
    bcname ARIA256       = BOTAN_BLOCK_CIPHER_ARIA_256
    bcname Blowfish      = BOTAN_BLOCK_CIPHER_BLOWFISH
    bcname Camellia128   = BOTAN_BLOCK_CIPHER_CAMELLIA_128
    bcname Camellia192   = BOTAN_BLOCK_CIPHER_CAMELLIA_192
    bcname Camellia256   = BOTAN_BLOCK_CIPHER_CAMELLIA_256
    bcname (Cascade bc1 bc2) = BOTAN_BLOCK_CIPHER_CASCADE /$ commas
        [ bcname bc1
        , bcname bc2
        ]
    bcname CAST128       = BOTAN_BLOCK_CIPHER_CAST_128
    bcname DES           = BOTAN_BLOCK_CIPHER_DES
    bcname TripleDES     = BOTAN_BLOCK_CIPHER_TRIPLEDES
    bcname GOST_28147_89 = BOTAN_BLOCK_CIPHER_GOST_28147_89
    bcname IDEA          = BOTAN_BLOCK_CIPHER_IDEA
    bcname (Lion h streamCiph optBlockSize) = BOTAN_BLOCK_CIPHER_LION /$ commas
        [ hashName h
        , streamCiph
        , maybe "" prn optBlockSize
        ]
    bcname Noekeon       = BOTAN_BLOCK_CIPHER_NOEKEON
    bcname SEED          = BOTAN_BLOCK_CIPHER_SEED
    bcname Serpent       = BOTAN_BLOCK_CIPHER_SERPENT
    bcname SHACAL2       = BOTAN_BLOCK_CIPHER_SHACAL2
    bcname SM4           = BOTAN_BLOCK_CIPHER_SM4
    bcname Threefish512  = BOTAN_BLOCK_CIPHER_THREEFISH_512
    bcname Twofish       = BOTAN_BLOCK_CIPHER_TWOFISH

-- TODO Newtype this
newtype BlockCipher128Type = MkBlockCipher128Type { un :: BlockCipherType }
    deriving newtype (Eq, Ord, Show)

blockCipher128Type :: BlockCipherType -> Maybe BlockCipher128Type
blockCipher128Type bc | isBlockCipher128Type bc = Just $ MkBlockCipher128Type bc
blockCipher128Type _ = Nothing

isBlockCipher128Type :: BlockCipherType -> Bool
isBlockCipher128Type AES128 = True
isBlockCipher128Type AES192 = True
isBlockCipher128Type AES256 = True
isBlockCipher128Type ARIA128 = True
isBlockCipher128Type ARIA192 = True
isBlockCipher128Type ARIA256 = True
isBlockCipher128Type Camellia128 = True
isBlockCipher128Type Camellia192 = True
isBlockCipher128Type Camellia256 = True
isBlockCipher128Type Noekeon = True
isBlockCipher128Type SEED = True
isBlockCipher128Type Serpent = True
isBlockCipher128Type SM4 = True
isBlockCipher128Type Twofish = True
isBlockCipher128Type _ = False

blockCipher128Name :: BlockCipher128Type -> ByteString
blockCipher128Name (MkBlockCipher128Type bc) = blockCipherName bc

--

{-
Statically-calculated block cipher block sizes
-}

blockCipherBlockSize :: BlockCipherType -> Int
blockCipherBlockSize Blowfish      = 8
blockCipherBlockSize CAST128       = 8
blockCipherBlockSize DES           = 8
blockCipherBlockSize TripleDES     = 8
blockCipherBlockSize GOST_28147_89 = 8
blockCipherBlockSize IDEA          = 8
blockCipherBlockSize AES128        = 16
blockCipherBlockSize AES192        = 16
blockCipherBlockSize AES256        = 16
blockCipherBlockSize ARIA128       = 16
blockCipherBlockSize ARIA192       = 16
blockCipherBlockSize ARIA256       = 16
blockCipherBlockSize Camellia128   = 16
blockCipherBlockSize Camellia192   = 16
blockCipherBlockSize Camellia256   = 16
blockCipherBlockSize Noekeon       = 16
blockCipherBlockSize SEED          = 16
blockCipherBlockSize Serpent       = 16
blockCipherBlockSize SM4           = 16
blockCipherBlockSize Twofish       = 16
blockCipherBlockSize SHACAL2       = 32
blockCipherBlockSize Threefish512  = 64
blockCipherBlockSize (Cascade bc1 bc2) = error "Unimplemented: blockCipherBlockSize"
blockCipherBlockSize (Lion h streamCiph optBlockSize) = error "Unimplemented: blockCipherBlockSize"
{-# WARNING blockCipherBlockSize "Unimplemented for: Cascade, Lion" #-}

generateBlockCipherBlockSizes :: IO ()
generateBlockCipherBlockSizes = do
    each <- forM blockCiphers  $ \ bc -> do
        mbc <- blockCipherInit bc
        bsz <- blockCipherGetBlockSize mbc
        return $ concat $
            [ "blockCipherBlockSize "
            , showsPrec 11 bc ""
            , " = "
            , show bsz
            ]
    putStrLn $ unlines $
        "blockCipherBlockSize :: BlockCipher -> Int"
        : each

{-
Statically-calculated block cipher key specs
-}
blockCipherKeySpec :: BlockCipherType -> SizeSpec BlockCipherKey
blockCipherKeySpec Blowfish      = sizeSpec 1 56 1
blockCipherKeySpec CAST128       = sizeSpec 11 16 1
blockCipherKeySpec DES           = sizeSpec 8 8 1
blockCipherKeySpec TripleDES     = sizeSpec 16 24 8
blockCipherKeySpec GOST_28147_89 = sizeSpec 32 32 1
blockCipherKeySpec IDEA          = sizeSpec 16 16 1
blockCipherKeySpec AES128        = sizeSpec 16 16 1
blockCipherKeySpec AES192        = sizeSpec 24 24 1
blockCipherKeySpec AES256        = sizeSpec 32 32 1
blockCipherKeySpec ARIA128       = sizeSpec 16 16 1
blockCipherKeySpec ARIA192       = sizeSpec 24 24 1
blockCipherKeySpec ARIA256       = sizeSpec 32 32 1
blockCipherKeySpec Camellia128   = sizeSpec 16 16 1
blockCipherKeySpec Camellia192   = sizeSpec 24 24 1
blockCipherKeySpec Camellia256   = sizeSpec 32 32 1
blockCipherKeySpec Noekeon       = sizeSpec 16 16 1
blockCipherKeySpec SEED          = sizeSpec 16 16 1
blockCipherKeySpec Serpent       = sizeSpec 16 32 8
blockCipherKeySpec SM4           = sizeSpec 16 16 1
blockCipherKeySpec Twofish       = sizeSpec 16 32 8
blockCipherKeySpec SHACAL2       = sizeSpec 16 64 4
blockCipherKeySpec Threefish512  = sizeSpec 64 64 1
blockCipherKeySpec (Cascade bc1 bc2) = error "Unimplemented: blockCipherKeySpec"
blockCipherKeySpec (Lion h streamCiph optBlockSize) = error "Unimplemented: blockCipherKeySpec"
{-# WARNING blockCipherKeySpec "Unimplemented for: Cascade, Lion" #-}

generateBlockCipherKeySpecs :: IO ()
generateBlockCipherKeySpecs = do
    each <- forM blockCiphers  $ \ bc -> do
        mbc <- blockCipherInit bc
        spec <- blockCipherGetKeyspec mbc
        return $ concat $
            [ "blockCipherKeySpec "
            , showsPrec 11 bc ""
            , " = "
            , showsPrec 11 spec ""
            ]
    putStrLn $ unlines $
        "blockCipherKeySpec :: BlockCipherType -> SizeSpec BlockCipherKey"
        : each

blockCiphers :: [BlockCipherType]
blockCiphers = (fmap (.un) blockCipher128s) ++ nonBlockCipher128s

blockCipher128s :: [BlockCipher128Type]
blockCipher128s = fmap MkBlockCipher128Type
    [ AES128
    , AES192
    , AES256
    , ARIA128
    , ARIA192
    , ARIA256
    , Camellia128
    , Camellia192
    , Camellia256
    , Noekeon
    , SEED
    , Serpent
    , SM4
    , Twofish
    ]

nonBlockCipher128s :: [BlockCipherType]
nonBlockCipher128s =
    [ Blowfish
    -- , Cascade
    , CAST128
    , DES
    , TripleDES
    , GOST_28147_89
    , IDEA
    -- , Lion
    , SHACAL2
    , Threefish512
    ]

---

{- |
Statically-calculated preferred key size

NOTE: We could use maxSize here, but this isn't always true for other categories
-}
blockCipherPreferredKeySize :: BlockCipherType -> Int
blockCipherPreferredKeySize Blowfish      = 56
blockCipherPreferredKeySize CAST128       = 16
blockCipherPreferredKeySize DES           = 8
blockCipherPreferredKeySize TripleDES     = 24
blockCipherPreferredKeySize GOST_28147_89 = 32
blockCipherPreferredKeySize IDEA          = 16
blockCipherPreferredKeySize AES128        = 16
blockCipherPreferredKeySize AES192        = 24
blockCipherPreferredKeySize AES256        = 32
blockCipherPreferredKeySize ARIA128       = 16
blockCipherPreferredKeySize ARIA192       = 24
blockCipherPreferredKeySize ARIA256       = 32
blockCipherPreferredKeySize Camellia128   = 16
blockCipherPreferredKeySize Camellia192   = 24
blockCipherPreferredKeySize Camellia256   = 32
blockCipherPreferredKeySize Noekeon       = 16
blockCipherPreferredKeySize SEED          = 16
blockCipherPreferredKeySize Serpent       = 32
blockCipherPreferredKeySize SM4           = 16
blockCipherPreferredKeySize Twofish       = 32
blockCipherPreferredKeySize SHACAL2       = 64
blockCipherPreferredKeySize Threefish512  = 64
blockCipherPreferredKeySize (Cascade bc1 bc2) = error "Unimplemented: blockCipherPreferredKeySize"
blockCipherPreferredKeySize (Lion h streamCiph optBlockSize) = error "Unimplemented: blockCipherPreferredKeySize"
{-# WARNING blockCipherPreferredKeySize "Unimplemented for: Cascade, Lion" #-}

generateBlockCipherKey :: BlockCipherType -> Int -> IO (Maybe BlockCipherKey)
generateBlockCipherKey bcType sz | validSize (blockCipherKeySpec bcType) sz
    = Just <$> userThreadsafeRNGGet sz
generateBlockCipherKey _ _ = pure Nothing

generatePreferredBlockCipherKey :: BlockCipherType -> IO BlockCipherKey
generatePreferredBlockCipherKey bcType = userThreadsafeRNGGet (blockCipherPreferredKeySize bcType)
