{-# LANGUAGE OverloadedStrings #-}

module Botan.Cipher
(   Cipher(..)
,   CipherKey
,   CipherNonce
,   CipherText
,   CipherInitFlags(..)
,   cipherInitFlags
,   CipherUpdateFlags(..)
,   cipherUpdateFlags
,   withCipher
,   cipherInit
,   cipherGetName
,   cipherGetOutputLength
,   cipherGetValidNonceLength
,   cipherGetTagLength
,   cipherGetDefaultNonceLength
,   cipherGetUpdateGranularity
,   cipherGetIdealUpdateGranularity
,   cipherGetKeyspec
,   cipherSetKey
,   cipherReset
,   cipherClear
,   cipherSetAssociatedData
,   cipherStart
,   cipherUpdate
,   cipherGetEstimateOutputLength
,   cipherGetEstimateFinalOutputLength
,   cipherUpdateChunk
,   cipherEncrypt
,   cipherDecrypt
,   encrypt
,   decrypt
-- ,   aeadEncrypt
-- ,   aeadDecrypt
-- NOTE: These two are sus - can't remember how well they were working
,   cipherEncryptOnline
,   cipherDecryptOnline
,   CipherType(..)
,   gcmMode
,   ocbMode
,   ccmMode
,   CBCPaddingType(..)
,   cbcPaddingTypeName
,   AEADType(..)
,   aeadType
,   isAEADType
,   ciphers
,   cbcPaddings
,   aeads
,   cipherName
,   cipherKeySpec
,   cipherDefaultNonceSize
,   cipherNonceSizeIsValid
,   cipherTagSize
,   cipherUpdateGranularity
,   cipherIdealUpdateGranularity
,   cipherOutputLength
,   generateCipherKeySpecs
,   generateCipherDefaultNonceLengths
,   generateCipherTagLength
,   generateCipherNonceLengths
,   generateCipherUpdateGranularity
,   generateCipherKey
,   cipherPreferredKeySize
,   generatePreferredCipherKey
,   generateCipherNonce
,   cipherPreferredNonceSize
,   generatePreferredCipherNonce
) where

import Botan.Internal.Prelude
import Botan.BlockCipher
import Botan.Bindings.Cipher
import Botan.RNG

import qualified Data.ByteString as ByteString

-- NOTE: There is still work to be done here separating encryptors from decryptors
-- Right now nothing stops the user from trying to decrypt with an encryptor and
-- vice versa, aside from Botan throwing an error
-- Ditto for ergonomics, the cipherEncrypt function is pointless if we still
-- have to set it all up first, need an encrypt / decrypt one-shots

-- TODO: Consider cipherNonceSize(IsValid) vs cipherNonceSpec

{-
Bindings Memorized instance
-}

instance Memorized BotanCipher where
    type Memo BotanCipher = Ptr
    type MemRep BotanCipher = BotanCipherStruct
    withMemo (MkBotanCipher ptr) action = action ptr

{-
BlockCipher object
-}

newtype Cipher = MkCipher { foreignPtr :: ForeignPtr BotanCipherStruct }

instance Memorized Cipher where
    type Memo Cipher = ForeignPtr
    type MemRep Cipher = BotanCipherStruct
    withMemo (MkCipher fptr) action = action fptr

instance BotanObject Cipher where

    type BotanStruct Cipher = BotanCipherStruct
    type BotanPtr    Cipher = BotanCipher

    toBotanPtr = MkBotanCipher
    toBotan    = MkCipher
    botanFinalizer  = botan_cipher_destroy

{-
Cipher ~~keys~~ types
-}

type CipherKey = ByteString
type CipherNonce = ByteString
type CipherText = ByteString

data CipherInitFlags =
    CipherMaskDirection
  | CipherEncrypt
  | CipherDecrypt
  deriving stock (Show, Eq)

-- TODO: Make these adhere to bitflag / bitfield
cipherInitFlags :: CipherInitFlags -> Word32
cipherInitFlags CipherMaskDirection = BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION
cipherInitFlags CipherEncrypt       = BOTAN_CIPHER_INIT_FLAG_ENCRYPT
cipherInitFlags CipherDecrypt       = BOTAN_CIPHER_INIT_FLAG_DECRYPT

data CipherUpdateFlags =
    CipherUpdate
  | CipherFinal
  deriving stock (Show, Eq)

-- TODO: Make these adhere to bitflag / bitfield
cipherUpdateFlags :: CipherUpdateFlags -> Word32
cipherUpdateFlags CipherUpdate = BOTAN_CIPHER_UPDATE_FLAG_NONE
cipherUpdateFlags CipherFinal  = BOTAN_CIPHER_UPDATE_FLAG_FINAL

{-
Cipher functions
-}

withCipher :: Cipher -> (BotanCipher -> IO a) -> IO a
withCipher = withBotanPtr @Cipher


-- |Initialize a cipher object
cipherInit :: CipherType -> CipherInitFlags -> IO Cipher
cipherInit cipherType flags = useAsCString (cipherName cipherType) $ \ namePtr -> do
    createBotan @Cipher $ \ outPtr -> botan_cipher_init outPtr
        (ConstPtr namePtr)
        (cipherInitFlags flags)

-- |Return the name of the cipher object
cipherGetName :: Cipher -> IO ByteString
cipherGetName = botanObjectName botan_cipher_name

-- |Return the output length of this cipher, for a particular input length.
--
--  WARNING: This function is of limited use. From the C++ docs:
--   /**
--   * Returns the size of the output if this transform is used to process a
--   * message with input_length bytes. In most cases the answer is precise.
--   * If it is not possible to precise (namely for CBC decryption) instead an
--   * upper bound is returned.
--   */
--  We need to explicitly calculate padding + tag length
cipherGetOutputLength
    :: Cipher   -- ^ __cipher__
    -> Int      -- ^ __in_len__
    -> IO Int   -- ^ __out_len__
-- cipherOutputLength = mkGetSize_csize withCipher botan_cipher_output_length
-- cipherOutputLength cipher inputLen = withCipher cipher $ \ cipherPtr -> do
--     alloca $ \ outLenPtr -> do
--         throwBotanIfNegative_ $ botan_cipher_output_length cipherPtr (fromIntegral inputLen) outLenPtr
--         fromIntegral <$> peek outLenPtr
-- NOTE: Technically this takes an extra argument but we shim it in with a lambda
-- rather than defining a custom function just for that
cipherGetOutputLength cipher inputLen = botanObjectIntegral
    (\ cipherPtr -> botan_cipher_output_length cipherPtr (fromIntegral inputLen)) cipher

-- NOTE: Unique function form?
-- |Return if the specified nonce length is valid for this cipher
-- NOTE: This just always seems to return 'True', even for -1 and maxBound
cipherGetValidNonceLength
    :: Cipher   -- ^ __cipher__
    -> Int      -- ^ __nl__
    -> IO Bool
-- cipherValidNonceLength = mkGetBoolCode_csize withCipher botan_cipher_valid_nonce_length
cipherGetValidNonceLength cipher nonceLen = withCipher cipher $ \ cipherPtr -> do
    code <- throwBotanIfNegative $ botan_cipher_valid_nonce_length cipherPtr (fromIntegral nonceLen)
    pure $ code == BOTAN_FFI_SUCCESS

-- |Get the tag length of the cipher (0 for non-AEAD modes)
cipherGetTagLength
    :: Cipher   -- ^ __cipher__
    -> IO Int   -- ^ __tag_size__
-- cipherGetTagLength = mkGetSize withCipher botan_cipher_get_tag_length
-- cipherGetTagLength cipher = withCipher cipher $ \ cipherPtr -> do
--     alloca $ \ tagLenPtr -> do
--         throwBotanIfNegative_ $ botan_cipher_get_tag_length cipherPtr tagLenPtr
--         fromIntegral <$> peek tagLenPtr
cipherGetTagLength = botanObjectIntegral botan_cipher_get_tag_length

-- |Get the default nonce length of this cipher
cipherGetDefaultNonceLength
    :: Cipher   -- ^ __cipher__
    -> IO Int   -- ^ __nl__
-- cipherGetDefaultNonceLength cipher = withCipher cipher $ \ cipherPtr -> do
--     alloca $ \ nonceLenPtr -> do
--         throwBotanIfNegative_ $ botan_cipher_get_default_nonce_length cipherPtr nonceLenPtr
--         fromIntegral <$> peek nonceLenPtr
cipherGetDefaultNonceLength = botanObjectIntegral botan_cipher_get_default_nonce_length

-- |Return the update granularity of the cipher; botan_cipher_update must be
--  called with blocks of this size, except for the final.
cipherGetUpdateGranularity
    :: Cipher   -- ^ __cipher__
    -> IO Int   -- ^ __ug__
-- cipherGetUpdateGranularity = mkGetSize withCipher botan_cipher_get_update_granularity
cipherGetUpdateGranularity = botanObjectIntegral botan_cipher_get_update_granularity

-- |Return the ideal update granularity of the cipher. This is some multiple of the
--  update granularity, reflecting possibilities for optimization.
--
-- Some ciphers (ChaChaPoly, EAX) may consume less input than the reported ideal granularity
cipherGetIdealUpdateGranularity
    :: Cipher   -- ^ __cipher__
    -> IO Int   -- ^ __ug__
-- cipherGetIdealUpdateGranularity = mkGetSize withCipher botan_cipher_get_ideal_update_granularity
cipherGetIdealUpdateGranularity = botanObjectIntegral botan_cipher_get_ideal_update_granularity

-- -- |Get information about the key lengths.
-- cipherQueryKeylen
--     :: Cipher       -- ^ __cipher__
--     -> IO (Int,Int) -- ^ __(min,max)__
-- cipherQueryKeylen = mkGetSizes2 withCipher botan_cipher_query_keylen
-- {-# DEPRECATED cipherQueryKeylen "Prefer cipherGetKeyspec." #-}

-- |Get information about the supported key lengths.
-- cipherGetKeyspec
--     :: Cipher           -- ^ __cipher__
--     -> IO (Int,Int,Int) -- ^ __(min,max,mod)__
-- cipherGetKeyspec = mkGetSizes3 withCipher botan_cipher_get_keyspec
cipherGetKeyspec :: Cipher -> IO (SizeSpec CipherKey)
cipherGetKeyspec = botanObjectKeyspec botan_cipher_get_keyspec

-- |Set the key for this cipher object
cipherSetKey
    :: Cipher       -- ^ __cipher__
    -> ByteString   -- ^ __key__
    -> IO ()
cipherSetKey cipher key = mask_ $ withCipher cipher $ \ cipherPtr -> do
    withPtr key $ \ keyPtr -> do
        throwBotanIfNegative_ $ botan_cipher_set_key cipherPtr
            (ConstPtr keyPtr)
            (fromIntegral (ByteString.length key))

-- |Reset the message specific state for this cipher.
--  Without resetting the keys, this resets the nonce, and any state
--  associated with any message bits that have been processed so far.
--
--  It is conceptually equivalent to calling botan_cipher_clear followed
--  by botan_cipher_set_key with the original key.
cipherReset
    :: Cipher   -- ^ __cipher__
    -> IO ()
-- cipherReset = mkAction withCipher botan_cipher_reset
cipherReset cipher = mask_ $ withCipher cipher $ \ cipherPtr -> do
    throwBotanIfNegative_ $ botan_cipher_reset cipherPtr

-- |Reset the key, nonce, AD and all other state on this cipher object
cipherClear :: Cipher -> IO ()
-- cipherClear = mkAction withCipher botan_cipher_clear
cipherClear cipher = mask_ $ withCipher cipher $ \ cipherPtr -> do
    throwBotanIfNegative_ $ botan_cipher_clear cipherPtr

-- |Set the associated data. Will fail if cipher is not an AEAD
cipherSetAssociatedData
    :: Cipher       -- ^ __cipher__
    -> ByteString   -- ^ __ad__
    -> IO ()
-- cipherSetAssociatedData = mkWithObjectSetterCBytesLen withCipher botan_cipher_set_associated_data
cipherSetAssociatedData cipher ad = mask_ $ withCipher cipher $ \ cipherPtr -> do
    withPtr ad $ \ adPtr -> do
        throwBotanIfNegative_ $ botan_cipher_set_associated_data
            cipherPtr
            (ConstPtr adPtr)
            (fromIntegral (ByteString.length ad))

-- |Begin processing a new message using the provided nonce
cipherStart
    :: Cipher       -- ^ __cipher__
    -> CipherNonce   -- ^ __nonce__
    -> IO ()
-- cipherStart = mkWithObjectSetterCBytesLen withCipher botan_cipher_start
-- NOTE: This is the same as cipherSetKey, candidate for convenience function
cipherStart cipher nonce = mask_ $ withCipher cipher $ \ cipherPtr -> do
    withPtr nonce $ \ noncePtr -> do
        throwBotanIfNegative_ $ botan_cipher_start cipherPtr
            (ConstPtr noncePtr)
            (fromIntegral (ByteString.length nonce))

-- |"Encrypt some data"
--
--  This function is ill-documented.
--
--  See the source for authoritative details:
--  https://github.com/randombit/botan/blob/72dc18bbf598f2c3bef81a4fb2915e9c3c524ac4/src/lib/ffi/ffi_cipher.cpp#L133
--
-- Some ciphers (ChaChaPoly, EAX) may consume less input than the reported ideal granularity
cipherUpdate ::
     Cipher               -- ^ __cipher__
  -> CipherUpdateFlags    -- ^ __flags__
  -> Int                  -- ^ __output_size__
  -> ByteString           -- ^ __input_bytes[]__
  -> IO (Int,ByteString)  -- ^ __(input_consumed,output[])__
-- cipherUpdate ctx flags outputSz input =
--     withCipher ctx $ \ ctxPtr ->
--     unsafeAsBytesLen input $ \ inputPtr inputSz ->
--     alloca $ \ consumedPtr ->
--     alloca $ \ writtenPtr -> do
--       eithOutput <-
--         try $ allocBytes outputSz $ \ outputPtr ->do
--           throwBotanIfNegative_ $ botan_cipher_update
--               ctxPtr
--               (cipherUpdateFlags flags)
--               outputPtr
--               (fromIntegral outputSz)
--               writtenPtr
--               (ConstPtr inputPtr)
--               inputSz
--               consumedPtr
--       -- If inssuficient buffer space, try again
--       output <- case eithOutput of
--         Left InsufficientBufferSpaceException{} -> do
--           outputSz' <- peek writtenPtr
--           allocBytes (fromIntegral outputSz') $ \ outputPtr ->do
--             throwBotanIfNegative_ $ botan_cipher_update
--                 ctxPtr
--                 (cipherUpdateFlags flags)
--                 outputPtr
--                 outputSz'
--                 writtenPtr
--                 (ConstPtr inputPtr)
--                 -- No input should be provided on the second try if the first
--                 -- try had the FINAL flags set
--                 (if flags == CipherFinal then 0 else inputSz)
--                 consumedPtr
--         Right bs -> pure bs
--       consumed <- fromIntegral <$> peek consumedPtr
--       written <- fromIntegral <$> peek writtenPtr
--       -- NOTE: The safety of this function is suspect - may require deepseq
--       let processed = ByteString.take written output
--           in processed `seq` return (consumed,processed)
cipherUpdate cipher flags outputSz input =
    mask_ $ withCipher cipher $ \ cipherPtr ->
    withPtrLen input $ \ inputPtr inputSz ->
    allocaMany @[CSize, CSize] $ \ (consumedPtr :> writtenPtr :> PNil) -> do
        -- Try once in case outputSz is sufficient
        attempt <- try $ allocInit ByteStringAllocator outputSz $ \ fPtr ->
            withPtr fPtr $ \ outputPtr -> do
            throwBotanIfNegative_ $ botan_cipher_update
                cipherPtr
                (cipherUpdateFlags flags)
                outputPtr
                (fromIntegral outputSz)
                writtenPtr
                (ConstPtr inputPtr)
                (fromIntegral inputSz)
                consumedPtr
        -- Peek at the actual required output size and try again if necessary
        output <- case attempt of
            Left (InsufficientBufferSpaceException{}) -> do
                requiredSz <- peek writtenPtr
                allocInit ByteStringAllocator outputSz $ \ fPtr ->
                    withPtr fPtr $ \ outputPtr -> do
                        throwBotanIfNegative_ $ botan_cipher_update
                            cipherPtr
                            (cipherUpdateFlags flags)
                            outputPtr
                            (fromIntegral requiredSz)
                            writtenPtr
                            (ConstPtr inputPtr)
                            -- No input should be provided on the second try if the first
                            -- try had the FINAL flags set
                            -- CLARIFY: Is this because it will already have consumed the
                            -- input on the first attempt, but still has the output pending?
                            -- This may explain many oddities of the API design
                            (if flags == CipherFinal then 0 else fromIntegral inputSz)
                            consumedPtr
            Right bs -> pure bs
        consumed <- fromIntegral <$> peek consumedPtr
        written  <- fromIntegral <$> peek writtenPtr
        -- NOTE: The safety of this function is suspect - may require deepseq
        let processed = ByteString.take written output
            in processed `seq` return (consumed,processed)

{-
Non-standard functions
-}

-- NOTE: out + ug + tag is safe overestimate for encryption
-- NOTE: out + ug - tag may not be a safe overestimate for decryption
cipherGetEstimateOutputLength :: Cipher -> CipherInitFlags -> Int -> IO Int
cipherGetEstimateOutputLength ctx flags input = do
    o <- cipherGetOutputLength ctx input  -- NOTE: Flawed but usable
    u <- cipherGetUpdateGranularity ctx -- TODO: When u == 1, it should be just input + t, right?
    t <- cipherGetTagLength ctx
    if flags == CipherEncrypt
        then return (o + u + t)
        else return (o + u - t) -- TODO: Maybe just 'o'...

-- NOTE: Offset must be a valid length of the input so far processed
-- NOTE: If (estimated) outputLength input + offset == outputLength (input + offset) then
--  we can just use cipherEstimateOutputLength instead of this
--  However, this may not be completely true due to block alignment requirements
--  For the moment this function exists for clarity.
cipherGetEstimateFinalOutputLength :: Cipher -> CipherInitFlags -> Int -> Int -> IO Int
cipherGetEstimateFinalOutputLength ctx flags offset input = do
    len <- cipherGetEstimateOutputLength ctx flags (offset + input)
    return $ len - offset

-- A better version of cipherUpdate
-- NOTE: It returns (processed,remaining) compared to (consumed,processed)
--  so the processed ciphertext has moved from snd to fst
-- TODO: Use Builder to do this?
--  https://hackage.haskell.org/package/bytestring-0.12.0.2/docs/Data-ByteString-Builder.html
-- NOTE: ByteString take and drop are efficient zero-copy operations so this is fine
-- NOTE: Renamed from cipherProcess to cipherUpdateChunk
cipherUpdateChunk :: Cipher -> CipherUpdateFlags -> Int -> ByteString -> IO (ByteString,ByteString)
-- cipherProcess ctx flags outputSz input = do
--     (consumed,processed) <- cipherUpdate ctx flags outputSz input
--     -- NOTE: The safety of this function is suspect - may require deepseq
--     let remaining = ByteString.drop consumed input
--         in processed `seq` remaining `seq` return (processed,remaining)
cipherUpdateChunk cipher flags outputSz input = do
    (consumed,processed) <- cipherUpdate cipher flags outputSz input
    pure (processed, ByteString.drop consumed input)

-- NOTE: Formerly cipherProcessOffline
cipherProcess :: Cipher -> CipherInitFlags -> ByteString -> IO ByteString
cipherProcess ctx flags msg = do
    o <- cipherGetEstimateOutputLength ctx flags (ByteString.length msg)
    -- snd <$> cipherUpdate ctx BOTAN_CIPHER_UPDATE_FLAG_FINAL o msg
    fst <$> cipherUpdateChunk ctx CipherFinal o msg

-- TODO: convenience: cipherFinalize

{- |
Encrypt and finalize a complete piece of data.

This is not a canonical Botan C/C++ function.
-}
cipherEncrypt :: Cipher -> ByteString -> IO CipherText
cipherEncrypt ctx = cipherProcess ctx CipherEncrypt

{- |
Encrypt and finalize a complete piece of data.

This is not a canonical Botan C/C++ function.
-}
cipherDecrypt :: Cipher -> CipherText -> IO ByteString
cipherDecrypt ctx = cipherProcess ctx CipherDecrypt

encrypt :: CipherType -> CipherKey -> CipherNonce -> ByteString -> IO CipherText
encrypt cipherType key nonce msg = do
    c <- cipherInit cipherType CipherEncrypt
    cipherSetKey c key
    cipherStart c nonce
    cipherEncrypt c msg

decrypt :: CipherType -> CipherKey -> CipherNonce -> CipherText -> IO ByteString
decrypt cipherType key nonce ct = do
    c <- cipherInit cipherType CipherDecrypt
    cipherSetKey c key
    cipherStart c nonce
    cipherDecrypt c ct

-- TODO: encryptAEAD, decryptAEAD

{-
Experiments with online processing
-}

-- TODO: Rename / refactor to cipherEncryptLazy
cipherEncryptOnline :: Cipher -> ByteString -> IO ByteString
cipherEncryptOnline ctx msg = do
    g <- cipherGetIdealUpdateGranularity ctx
    ByteString.concat <$> go 0 g msg
    where
        go i g bs = case ByteString.splitAt g bs of
            (block,"")      -> do
                o <- cipherGetEstimateFinalOutputLength ctx CipherEncrypt i (ByteString.length block)
                (processed,_) <- cipherUpdateChunk ctx CipherFinal o block
                return [processed]
            (block,rest)    -> do
                (processed,remaining) <- cipherUpdateChunk ctx CipherUpdate g block
                (processed :) <$> go (i + g) g (remaining <> rest)
                -- Though this following version may be more efficient especially with lazy bytestrings
                --  or builder, though note *which* update function it uses - the original
                -- (consumed,processed) <- cipherUpdate ctx BOTAN_CIPHER_UPDATE_FLAG_NONE g block
                -- (processed :) <$> go (i + g) g (ByteString.drop consumed bs)

-- TODO: Rename / refactor to cipherDecryptLazy
cipherDecryptOnline :: Cipher -> ByteString -> IO ByteString
cipherDecryptOnline ctx msg = do
    g <- cipherGetIdealUpdateGranularity ctx
    t <- cipherGetTagLength ctx
    ByteString.concat <$> go 0 g t msg
    where
        go i g t bs = case ByteString.splitAt g bs of
            (block,"")      -> do
                o <- cipherGetEstimateFinalOutputLength ctx CipherDecrypt i (ByteString.length block)
                (processed,_) <- cipherUpdateChunk ctx CipherFinal o block
                return [processed]
            (block,rest)    -> do
                (processed,remaining) <- cipherUpdateChunk ctx CipherUpdate g block
                (processed :) <$> go (i + g) g t (remaining <> rest)

{-
Cipher algorithms
-}

-- NOTE: In the base bindings, some algorithms allow you to omit parenthesis
-- arguments - for the moment, we will require them and provide convenience
-- initializers to populate default arguments
data CipherType
    = CBC BlockCipherType CBCPaddingType
    | CFB BlockCipherType Int -- Feedback bits size, default is 8 * block size
    | XTS BlockCipherType
    | ChaCha20Poly1305
    | GCM BlockCipher128Type Int -- Tag size, default is 16
    | OCB BlockCipher128Type Int -- Tag size, default is 16
    | EAX BlockCipherType Int -- Tag size, default is block size
    | SIV BlockCipher128Type
    | CCM BlockCipher128Type Int Int -- Tag size and L, default tag size is 16 and L is 3
    deriving stock (Eq, Ord, Show)

-- cfbMode :: CipherType
-- cfbMode bc = CFB bc (8 * blockCipherBlockSize bc)

gcmMode :: BlockCipher128Type -> CipherType
gcmMode bc = GCM bc 16

ocbMode :: BlockCipher128Type -> CipherType
ocbMode bc = OCB bc 16

-- eaxMode :: BlockCipherType -> CipherType
-- eaxMode bc = EAX bc (blockCipherBlockSize bc)

ccmMode :: BlockCipher128Type -> CipherType
ccmMode bc = CCM bc 16 3

cipherName :: CipherType -> ByteString
cipherName (CBC bc padding) = slashes
    [ blockCipherName bc
    , BOTAN_CIPHER_MODE_CBC
    , cbcPaddingTypeName padding
    ]
cipherName (CFB bc feedbackSz) = bcmode bc BOTAN_CIPHER_MODE_CFB (prn feedbackSz)
cipherName (XTS bc) = blockCipherName bc // BOTAN_CIPHER_MODE_XTS
cipherName ChaCha20Poly1305 = BOTAN_AEAD_CHACHA20POLY1305
cipherName (GCM (MkBlockCipher128Type bc) tagSz) = bcmode bc BOTAN_AEAD_MODE_GCM (prn tagSz)
cipherName (OCB (MkBlockCipher128Type bc) tagSz) = bcmode bc BOTAN_AEAD_MODE_OCB (prn tagSz)
cipherName (EAX bc tagSz) = bcmode bc BOTAN_AEAD_MODE_EAX (prn tagSz)
cipherName (SIV (MkBlockCipher128Type bc)) = blockCipherName bc // BOTAN_AEAD_MODE_SIV
cipherName (CCM (MkBlockCipher128Type bc) tagSz l) = bcmode bc BOTAN_AEAD_MODE_CCM $ commas
    [ prn tagSz
    , prn l
    ]

-- Internal helper
bcmode bc mode aux = blockCipherName bc // mode /$ aux

data CBCPaddingType
    = PKCS7
    | OneAndZeros
    | X9_23
    | ESP   -- NOTE: RFC 4304
    | CTS   -- NOTE: Ciphertext stealing
    | NoPadding
    deriving stock (Eq, Ord, Show)

cbcPaddingTypeName :: CBCPaddingType -> ByteString
cbcPaddingTypeName PKCS7 = BOTAN_CBC_PADDING_PKCS7
cbcPaddingTypeName OneAndZeros = BOTAN_CBC_PADDING_ONE_AND_ZEROS
cbcPaddingTypeName X9_23 = BOTAN_CBC_PADDING_X9_23
cbcPaddingTypeName ESP = BOTAN_CBC_PADDING_ESP
cbcPaddingTypeName CTS = BOTAN_CBC_PADDING_CTS
cbcPaddingTypeName NoPadding = BOTAN_CBC_PADDING_NO_PADDING

newtype AEADType = MkAEADType { un :: CipherType }
    deriving stock (Eq, Ord, Show)

aeadType :: CipherType -> Maybe AEADType
aeadType c | isAEADType c = Just $ MkAEADType c
aeadType _ = Nothing

isAEADType :: CipherType -> Bool
isAEADType c@(ChaCha20Poly1305) = True
isAEADType c@(GCM _ _)          = True
isAEADType c@(OCB _ _)          = True
isAEADType c@(EAX _ _)          = True
isAEADType c@(SIV _)            = True
isAEADType c@(CCM _ _ _)        = True
isAEADType _                    = False

ciphers :: [ CipherType ]
ciphers = concat
    [ [ CBC bc pd                               | bc <- blockCiphers, pd <- cbcPaddings ]
    , [ CFB bc (8 * blockCipherBlockSize bc)    | bc <- blockCiphers ]
    , [ XTS bc                                  | bc <- blockCiphers ]
    ,  fmap (.un) aeads
    ]

cbcPaddings :: [ CBCPaddingType ]
cbcPaddings =
    [ PKCS7
    , OneAndZeros
    , X9_23
    , ESP
    , CTS
    , NoPadding
    ]

aeads :: [ AEADType ]
aeads = fmap MkAEADType $ concat
    [ [ ChaCha20Poly1305 ]
    , [ GCM bc 16                               | bc <- blockCipher128s ]
    , [ OCB bc 16                               | bc <- blockCipher128s ]
    , [ EAX bc (blockCipherBlockSize bc)        | bc <- blockCiphers ]
    , [ SIV bc                                  | bc <- blockCipher128s ]
    , [ CCM bc 16 3                             | bc <- blockCipher128s ]
    ]

cipherKeySpec :: CipherType -> SizeSpec CipherKey
cipherKeySpec (CBC bc _)        = blockCipherKeySpec bc
cipherKeySpec (CFB bc _)        = blockCipherKeySpec bc
cipherKeySpec (XTS bc)          = mapSizes (*2) $ blockCipherKeySpec bc
cipherKeySpec ChaCha20Poly1305  = sizeSpec 32 32 1
cipherKeySpec (GCM bc128 _)     = blockCipherKeySpec bc128.un
cipherKeySpec (OCB bc128 _)     = blockCipherKeySpec bc128.un
cipherKeySpec (EAX bc _)        = blockCipherKeySpec bc
cipherKeySpec (SIV bc128)       = mapSizes (*2) $ blockCipherKeySpec bc128.un
cipherKeySpec (CCM bc128 _ _)   = blockCipherKeySpec bc128.un

generateCipherKeySpecs :: IO ()
generateCipherKeySpecs = do
    each <- forM ciphers  $ \ c -> do
        ctx <- cipherInit c CipherEncrypt
        spec <- cipherGetKeyspec ctx
        return $ concat $
            [ "cipherKeySpec "
            , showsPrec 11 c ""
            , " = "
            , showsPrec 11 spec ""
            ]
    putStrLn $ unlines $
        "cipherKeySpec :: Cipher -> CipherKeySpec"
        : each

-- TODO: Nomenclature - size vs length
cipherDefaultNonceSize :: CipherType -> Int
cipherDefaultNonceSize (CBC bc _) = blockCipherBlockSize bc
cipherDefaultNonceSize (CFB bc _) = blockCipherBlockSize bc
cipherDefaultNonceSize (XTS bc)   = blockCipherBlockSize bc
-- NOTE: This is the value at current, and matches the default in botan,
-- presumably because 12 is valid for all remaining cipher / AEAD nonces
cipherDefaultNonceSize _          = 12

generateCipherDefaultNonceLengths :: IO ()
generateCipherDefaultNonceLengths = do
    each <- forM ciphers  $ \ c -> do
        ctx <- cipherInit c CipherEncrypt
        nlen <- cipherGetDefaultNonceLength ctx
        return $ concat $
            [ "cipherDefaultNonceLength "
            , showsPrec 11 c ""
            , " = "
            , show nlen
            ]
    putStrLn $ unlines $
        "cipherDefaultNonceLength :: CipherType -> Int"
        : each


-- TODO: Make NonceSpec? generalize to RangeSpec?

-- NOTE: We've capped the length at 512, but they could be potentially unbounded
internalMaximumCipherNonceSize :: Int
internalMaximumCipherNonceSize = 1024

cipherNonceSizeIsValid :: Int -> CipherType -> Bool
cipherNonceSizeIsValid n (CBC bc _)         = n == blockCipherBlockSize bc
cipherNonceSizeIsValid n (CFB bc _)         = n == blockCipherBlockSize bc
cipherNonceSizeIsValid n (XTS bc)           = 1 <= n && n <= blockCipherBlockSize bc -- Always [ 1 .. 16 ]
cipherNonceSizeIsValid n ChaCha20Poly1305   = n `elem` [ 8, 12, 24 ] -- NOTE: Standard IETF ChaCha20Poly1305 requires 12, but botan seems more accepting
cipherNonceSizeIsValid n (GCM _ _)          = 1 <= n && n <= internalMaximumCipherNonceSize -- True if unbounded
cipherNonceSizeIsValid n (OCB bc128 _)      = 1 <= n && n <= blockCipherBlockSize bc128.un - 1 -- Always [ 1 .. 15 ]
cipherNonceSizeIsValid n (EAX _ _)          = 1 <= n && n <= internalMaximumCipherNonceSize -- True if unbounded
cipherNonceSizeIsValid n (SIV _)            = 1 <= n && n <= internalMaximumCipherNonceSize -- True if unbounded
cipherNonceSizeIsValid n (CCM _ _ _)        = n == 12

generateCipherNonceLengths :: IO ()
generateCipherNonceLengths = do
    each <- forM ciphers  $ \ c -> do
        ctx <- cipherInit c CipherEncrypt
        validLengths <- filterM (cipherGetValidNonceLength ctx) [1..512]
        return $ concat $
            [ "cipherValidNonceLengths "
            , showsPrec 11 c ""
            , " = "
            , show validLengths
            ]
    putStrLn $ unlines $
        "cipherValidNonceLengths :: CipherType -> [ Int ]"
        : each

cipherTagSize :: CipherType -> Maybe Int
cipherTagSize (CBC _bc _)       = Nothing
cipherTagSize (CFB _bc _)       = Nothing
cipherTagSize (XTS _bc)         = Nothing
cipherTagSize ChaCha20Poly1305  = Just 16
cipherTagSize (GCM _ tsz)       = Just tsz
cipherTagSize (OCB _ tsz)       = Just tsz
cipherTagSize (EAX _ tsz)       = Just tsz
cipherTagSize (SIV _)           = Just 16
cipherTagSize (CCM _ tsz _)     = Just tsz

generateCipherTagLength :: IO ()
generateCipherTagLength = do
    each <- forM ciphers  $ \ c -> do
        ctx <- cipherInit c CipherEncrypt
        tag <- cipherGetTagLength ctx
        return $ concat $
            [ "cipherTagLength "
            , showsPrec 11 c ""
            , " = "
            , show tag
            ]
    putStrLn $ unlines $
        "cipherTagLength :: CipherType -> Int"
        : each

cipherUpdateGranularity :: CipherType -> Int
cipherUpdateGranularity (CBC bc CTS)     = 2 * blockCipherBlockSize bc
cipherUpdateGranularity (CBC bc _)       = blockCipherBlockSize bc
cipherUpdateGranularity (CFB bc _)       = blockCipherBlockSize bc
cipherUpdateGranularity (XTS bc)         = 2 * blockCipherBlockSize bc
cipherUpdateGranularity ChaCha20Poly1305 = 1
cipherUpdateGranularity (GCM bc128 _)    = blockCipherBlockSize bc128.un -- always 16
cipherUpdateGranularity (OCB bc128 _)    = blockCipherBlockSize bc128.un -- always 16
cipherUpdateGranularity (EAX _ _)        = 1
cipherUpdateGranularity (SIV _)          = 1
cipherUpdateGranularity (CCM _ _ _)      = 1

generateCipherUpdateGranularity :: IO ()
generateCipherUpdateGranularity = do
    each <- forM ciphers  $ \ c -> do
        ctx <- cipherInit c CipherEncrypt
        ug <- cipherGetUpdateGranularity ctx
        return $ concat $
            [ "cipherUpdateGranularity "
            , showsPrec 11 c ""
            , " = "
            , show ug
            ]
    putStrLn $ unlines $
        "cipherUpdateGranularity :: CipherType -> Int"
        : each

cipherIdealUpdateGranularity :: CipherType -> Int
cipherIdealUpdateGranularity cipher = unsafePerformIO $ do
    ctx <- cipherInit cipher CipherEncrypt
    cipherGetIdealUpdateGranularity ctx
{-# NOINLINE cipherIdealUpdateGranularity #-}
-- NOTE: This is machine-dependent, but should stay consistent per-machine
-- so we do this instead of inlining the values

cipherOutputLength :: CipherType -> CipherInitFlags -> Int -> Int
cipherOutputLength c flags n = unsafePerformIO $ do
    ctx <- cipherInit c flags
    cipherGetOutputLength ctx n
{-# NOINLINE cipherOutputLength #-}


--

cipherPreferredKeySize :: CipherType -> Int
cipherPreferredKeySize (CBC bc _)        = blockCipherPreferredKeySize bc
cipherPreferredKeySize (CFB bc _)        = blockCipherPreferredKeySize bc
cipherPreferredKeySize (XTS bc)          = 2 * blockCipherPreferredKeySize bc
cipherPreferredKeySize ChaCha20Poly1305  = 32
cipherPreferredKeySize (GCM bc128 _)     = blockCipherPreferredKeySize bc128.un
cipherPreferredKeySize (OCB bc128 _)     = blockCipherPreferredKeySize bc128.un
cipherPreferredKeySize (EAX bc _)        = blockCipherPreferredKeySize bc
cipherPreferredKeySize (SIV bc128)       = 2 * blockCipherPreferredKeySize bc128.un
cipherPreferredKeySize (CCM bc128 _ _)   = blockCipherPreferredKeySize bc128.un

generateCipherKey :: CipherType -> Int -> IO (Maybe CipherKey)
generateCipherKey c sz | validSize (cipherKeySpec c) sz = Just <$> userThreadsafeRNGGet sz
generateCipherKey _ _ = pure Nothing

generatePreferredCipherKey :: CipherType -> IO CipherKey
generatePreferredCipherKey c = userThreadsafeRNGGet (cipherPreferredKeySize c)

cipherPreferredNonceSize :: CipherType -> Int
cipherPreferredNonceSize (CBC bc _)        = blockCipherBlockSize bc
cipherPreferredNonceSize (CFB bc _)        = blockCipherBlockSize bc
cipherPreferredNonceSize (XTS bc)          = 16
cipherPreferredNonceSize ChaCha20Poly1305  = 12 -- NOTE: Required by standard IETF ChaCha20Poly1305?
cipherPreferredNonceSize (GCM bc128 _)     = 12
cipherPreferredNonceSize (OCB bc128 _)     = 12
cipherPreferredNonceSize (EAX bc _)        = 12
cipherPreferredNonceSize (SIV bc128)       = 12
cipherPreferredNonceSize (CCM bc128 _ _)   = 12

generateCipherNonce :: CipherType -> Int -> IO (Maybe CipherNonce)
generateCipherNonce c sz | cipherNonceSizeIsValid sz c = Just <$> userThreadsafeRNGGet sz
generateCipherNonce _ _ = pure Nothing

generatePreferredCipherNonce :: CipherType -> IO CipherNonce
generatePreferredCipherNonce c = userThreadsafeRNGGet (cipherPreferredNonceSize c)
