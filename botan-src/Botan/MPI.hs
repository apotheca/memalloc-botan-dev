module Botan.MPI where

import Botan.Bindings.MPI
import Botan.Internal.Prelude
import Botan.RNG

import qualified Foreign.Ptr as Foreign
import qualified Data.ByteString as ByteString

instance Memorized BotanMP where
    type Memo BotanMP = Ptr
    type MemRep BotanMP = BotanMPStruct
    withMemo (MkBotanMP ptr) action = action ptr

newtype MP = MkMP { foreignPtr :: ForeignPtr BotanMPStruct }

instance Memorized MP where
    type Memo MP = ForeignPtr
    type MemRep MP = BotanMPStruct
    withMemo (MkMP fptr) action = action fptr

instance BotanObject MP where

    type BotanStruct MP = BotanMPStruct
    type BotanPtr    MP = BotanMP

    toBotanPtr = MkBotanMP
    toBotan    = MkMP
    botanFinalizer  = botan_mp_destroy

data MPFormat
    = MPDecimal
    | MPHexadecimal
    deriving stock (Eq, Ord, Show)

mpFormatRadix :: MPFormat -> Int
mpFormatRadix MPDecimal     = 10
mpFormatRadix MPHexadecimal = 16

withMP :: MP -> (BotanMP -> IO a) -> IO a
withMP = withBotanPtr @MP

mpInit :: IO MP
mpInit = createBotan @MP botan_mp_init

mpToHex :: MP -> IO ByteString
mpToHex mp = mask_ $ withMP mp $ \ mpPtr -> do
    numBytes <- mpNumBytes mp
    hex <- allocInit ByteStringAllocator (2 + (numBytes * 2) + 1) $ \ fPtr ->
        withPtr fPtr $ \ bytesPtr ->
        throwBotanIfNegative_ $ botan_mp_to_hex mpPtr (cast bytesPtr)
    return $!! ByteString.takeWhile (/= 0) hex

mpToStr :: MP -> MPFormat -> IO ByteString
mpToStr mp radix = mask_ $ withMP mp $ \ mpPtr -> do
    let base = fromIntegral (mpFormatRadix radix)
    n <- queryBufferLength $ \ szPtr -> botan_mp_to_str mpPtr base Foreign.nullPtr szPtr
    str <- alloca $ \ szPtr -> do
        poke szPtr (fromIntegral n)
        allocInit ByteStringAllocator n $ \ fPtr ->
            withPtr fPtr $ \ bytesPtr ->
            throwBotanIfNegative_ $ botan_mp_to_str mpPtr base (cast bytesPtr) szPtr
    return $!! ByteString.takeWhile (/= 0) str

mpClear :: MP -> IO ()
mpClear = botanObjectAction botan_mp_clear

mpSetFromInt :: MP -> Int -> IO ()
mpSetFromInt mp n = mask_ $ withMP mp $ \ mpPtr ->
    throwBotanIfNegative_ $ botan_mp_set_from_int mpPtr (fromIntegral n)

mpSetFromMP :: MP -> MP -> IO ()
mpSetFromMP = mpLiftUnary botan_mp_set_from_mp

mpCopy :: MP -> IO MP
mpCopy mp = do
    copy <- mpInit
    mpSetFromMP copy mp
    return copy

mpSetFromStr :: MP -> ByteString -> IO ()
mpSetFromStr mp str = mask_ $ withMP mp $ \ mpPtr ->
    useAsCString str $ \ strPtr ->
    throwBotanIfNegative_ $ botan_mp_set_from_str mpPtr (ConstPtr strPtr)

mpSetFromRadixStr :: MP -> MPFormat -> ByteString -> IO ()
mpSetFromRadixStr mp radix str = mask_ $ withMP mp $ \ mpPtr ->
    useAsCString str $ \ strPtr ->
    throwBotanIfNegative_ $ botan_mp_set_from_radix_str mpPtr
        (ConstPtr strPtr)
        (fromIntegral (mpFormatRadix radix))

mpNumBits :: MP -> IO Int
mpNumBits = botanObjectIntegral botan_mp_num_bits

mpNumBytes :: MP -> IO Int
mpNumBytes = botanObjectIntegral botan_mp_num_bytes

mpToBin :: MP -> IO ByteString
mpToBin mp = mask_ $ withMP mp $ \ mpPtr -> do
    numBytes <- mpNumBytes mp
    allocInit ByteStringAllocator numBytes $ \ fPtr ->
        withPtr fPtr $ \ bytesPtr ->
        throwBotanIfNegative_ $ botan_mp_to_bin mpPtr bytesPtr

mpFromBin :: MP -> ByteString -> IO ()
mpFromBin mp bytes = mask_ $ withMP mp $ \ mpPtr ->
    withPtrLen bytes $ \ bytesPtr bytesLen ->
    throwBotanIfNegative_ $ botan_mp_from_bin mpPtr
        (ConstPtr bytesPtr)
        (fromIntegral bytesLen)

mpToWord32 :: MP -> IO Word32
mpToWord32 = botanObjectStorable botan_mp_to_uint32

mpIsPositive :: MP -> IO Bool
mpIsPositive = mpLiftBool botan_mp_is_positive

mpIsNegative :: MP -> IO Bool
mpIsNegative = mpLiftBool botan_mp_is_negative

mpFlipSign :: MP -> IO ()
mpFlipSign = botanObjectAction botan_mp_flip_sign

mpIsZero :: MP -> IO Bool
mpIsZero = mpLiftBool botan_mp_is_zero

mpAddWord32 :: MP -> MP -> Word32 -> IO ()
mpAddWord32 result x y = mask_ $ withMP result $ \ resultPtr ->
    withMP x $ \ xPtr ->
    throwBotanIfNegative_ $ botan_mp_add_u32 resultPtr xPtr y

mpSubWord32 :: MP -> MP -> Word32 -> IO ()
mpSubWord32 result x y = mask_ $ withMP result $ \ resultPtr ->
    withMP x $ \ xPtr ->
    throwBotanIfNegative_ $ botan_mp_sub_u32 resultPtr xPtr y

mpAdd :: MP -> MP -> MP -> IO ()
mpAdd = mpLiftBinary botan_mp_add

mpSub :: MP -> MP -> MP -> IO ()
mpSub = mpLiftBinary botan_mp_sub

mpMul :: MP -> MP -> MP -> IO ()
mpMul = mpLiftBinary botan_mp_mul

mpDiv :: MP -> MP -> MP -> MP -> IO ()
mpDiv = mpLiftTrinary botan_mp_div

mpModMul :: MP -> MP -> MP -> MP -> IO ()
mpModMul = mpLiftTrinary botan_mp_mod_mul

mpEqual :: MP -> MP -> IO Bool
mpEqual a b = mask_ $ withMP a $ \ aPtr ->
    withMP b $ \ bPtr ->
    throwBotanCatchingBool $ botan_mp_equal aPtr bPtr

mpCmp :: MP -> MP -> IO Ordering
mpCmp a b = mask_ $ withMP a $ \ aPtr ->
    withMP b $ \ bPtr ->
    alloca $ \ resultPtr -> do
        throwBotanIfNegative_ $ botan_mp_cmp resultPtr aPtr bPtr
        result <- peek resultPtr
        return $ compare result 0

mpSwap :: MP -> MP -> IO ()
mpSwap = mpLiftUnary botan_mp_swap

mpPowMod :: MP -> MP -> MP -> MP -> IO ()
mpPowMod = mpLiftTrinary botan_mp_powmod

mpLeftShift :: MP -> MP -> Int -> IO ()
mpLeftShift = mpLiftInt botan_mp_lshift

mpRightShift :: MP -> MP -> Int -> IO ()
mpRightShift = mpLiftInt botan_mp_rshift

mpModInverse :: MP -> MP -> MP -> IO ()
mpModInverse = mpLiftBinary botan_mp_mod_inverse

mpRandBits :: MP -> RNG -> Int -> IO ()
mpRandBits mp rng bits = mask_ $ withMP mp $ \ mpPtr ->
    withRNG rng $ \ rngPtr ->
    throwBotanIfNegative_ $ botan_mp_rand_bits mpPtr rngPtr (fromIntegral bits)

mpRandRange :: MP -> RNG -> MP -> MP -> IO ()
mpRandRange mp rng lower upper = mask_ $ withMP mp $ \ mpPtr ->
    withRNG rng $ \ rngPtr ->
    withMP lower $ \ lowerPtr ->
    withMP upper $ \ upperPtr ->
    throwBotanIfNegative_ $ botan_mp_rand_range mpPtr rngPtr lowerPtr upperPtr

mpGCD :: MP -> MP -> MP -> IO ()
mpGCD = mpLiftBinary botan_mp_gcd

mpIsPrime :: MP -> RNG -> Int -> IO Bool
mpIsPrime mp rng probability = mask_ $ withMP mp $ \ mpPtr ->
    withRNG rng $ \ rngPtr ->
    throwBotanCatchingBool $ botan_mp_is_prime mpPtr rngPtr (fromIntegral probability)

mpGetBit :: MP -> Int -> IO Bool
mpGetBit mp bit = mask_ $ withMP mp $ \ mpPtr ->
    throwBotanCatchingBool $ botan_mp_get_bit mpPtr (fromIntegral bit)

mpSetBit :: MP -> Int -> IO ()
mpSetBit mp bit = mask_ $ withMP mp $ \ mpPtr ->
    throwBotanIfNegative_ $ botan_mp_set_bit mpPtr (fromIntegral bit)

mpClearBit :: MP -> Int -> IO ()
mpClearBit mp bit = mask_ $ withMP mp $ \ mpPtr ->
    throwBotanIfNegative_ $ botan_mp_clear_bit mpPtr (fromIntegral bit)

-- Helpers

mpLiftBool :: (BotanMP -> IO CInt) -> MP -> IO Bool
mpLiftBool f mp = mask_ $ withMP mp $ \ mpPtr ->
    throwBotanCatchingBool $ f mpPtr

mpLiftInt :: (BotanMP -> BotanMP -> CSize -> IO CInt) -> MP -> MP -> Int -> IO ()
mpLiftInt f dest source shift = mask_ $ withMP dest $ \ destPtr ->
    withMP source $ \ sourcePtr ->
    throwBotanIfNegative_ $ f destPtr sourcePtr (fromIntegral shift)

mpLiftUnary :: (BotanMP -> BotanMP -> IO CInt) -> MP -> MP -> IO ()
mpLiftUnary f dest source = mask_ $ withMP dest $ \ destPtr ->
    withMP source $ \ sourcePtr ->
    throwBotanIfNegative_ $ f destPtr sourcePtr

mpLiftBinary :: (BotanMP -> BotanMP -> BotanMP -> IO CInt) -> MP -> MP -> MP -> IO ()
mpLiftBinary f dest a b = mask_ $ withMP dest $ \ destPtr ->
    withMP a $ \ aPtr ->
    withMP b $ \ bPtr ->
    throwBotanIfNegative_ $ f destPtr aPtr bPtr

mpLiftTrinary :: (BotanMP -> BotanMP -> BotanMP -> BotanMP -> IO CInt) -> MP -> MP -> MP -> MP -> IO ()
mpLiftTrinary f dest a b c = mask_ $ withMP dest $ \ destPtr ->
    withMP a $ \ aPtr ->
    withMP b $ \ bPtr ->
    withMP c $ \ cPtr ->
    throwBotanIfNegative_ $ f destPtr aPtr bPtr cPtr
