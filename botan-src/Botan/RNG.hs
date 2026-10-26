{-# LANGUAGE AllowAmbiguousTypes, FunctionalDependencies, ImplicitParams, DefaultSignatures #-}

module Botan.RNG
(
    RNG(..)
,   withRNG
,   rngInit
,   rngGet
,   systemRNGGet
,   rngReseed
,   rngReseedFromRNG
,   rngAddEntropy
,   RNGType(..)
,   rngTypeName
,   systemRNG
,   userThreadsafeRNG
,   userThreadsafeRNGGet
) where

-- TODO: Botan Prelude

import System.IO.Unsafe (unsafePerformIO)
import Botan.Bindings.RNG
import Botan.Bindings.ConstPtr (ConstPtr (..))

import Botan.Internal.Object
import Botan.Internal.Error

import Memory.Memo
import Memory.Memo.Pointer
import Memory.Memo.Castable
import Memory.Allocator
import Memory.Allocator.ByteString

import Control.Monad (replicateM, forM, forM_)
import Data.IORef (IORef)
import Data.Void (Void)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Foreign.Ptr (Ptr)
import Foreign.ForeignPtr (ForeignPtr)

import Data.Maybe (fromMaybe)
import Control.Monad.ST (ST)
import qualified Control.Monad.ST as ST
import qualified Data.Array.ST as ST
import qualified Data.Array as Array
import qualified GHC.Arr as ST
import Data.Bits -- Aye... TODO: Prefer Memory.Bits


{-
Bindings Memorized instance
-}

instance Memorized BotanRNG where
    type Memo BotanRNG = Ptr
    type MemRep BotanRNG = BotanRNGStruct
    withMemo (MkBotanRNG ptr) action = action ptr

{-
RNG object
-}

newtype RNG = MkRNG { foreignPtr :: ForeignPtr BotanRNGStruct }

instance Memorized RNG where
    type Memo RNG = ForeignPtr
    type MemRep RNG = BotanRNGStruct
    withMemo (MkRNG fptr) action = action fptr

instance BotanObject RNG where

    type BotanStruct RNG = BotanRNGStruct
    type BotanPtr    RNG = BotanRNG

    toBotanPtr      = MkBotanRNG
    toBotan         = MkRNG
    botanFinalizer  = botan_rng_destroy

{-
RNG functions
-}

withRNG :: RNG -> (BotanRNG -> IO a) -> IO a
withRNG = withBotanPtr

-- TODO: Push ByteString.useAsCString out to a Memory helper using WithPtr
rngInit :: RNGType -> IO RNG
rngInit t = ByteString.useAsCString (rngTypeName t) $ \ tPtr -> do
    createBotan @RNG $ \ outPtr -> botan_rng_init outPtr (ConstPtr tPtr)

rngGet :: RNG -> Int -> IO ByteString
rngGet rng len = withRNG rng $ \ botanRNG -> do
    allocInit ByteStringAllocator len $ \ fPtr -> withPtr fPtr $ \ bytesPtr -> do
        throwBotanIfNegative_ $ botan_rng_get botanRNG bytesPtr (fromIntegral len)

systemRNGGet :: Int -> IO ByteString
systemRNGGet len = allocInit ByteStringAllocator len $ \ fPtr -> withPtr fPtr $ \ bytesPtr -> do
    throwBotanIfNegative_ $ botan_system_rng_get bytesPtr (fromIntegral len)

rngReseed :: RNG -> Int -> IO ()
rngReseed rng bits = withRNG rng $ \ botanRNG -> do
    throwBotanIfNegative_ $ botan_rng_reseed botanRNG (fromIntegral bits)

rngReseedFromRNG :: RNG -> RNG -> Int -> IO ()
rngReseedFromRNG rng source bits = withRNG rng $ \ botanRNG -> do
    withRNG source $ \ sourcePtr -> do
        throwBotanIfNegative_ $ botan_rng_reseed_from_rng botanRNG sourcePtr (fromIntegral bits)

rngAddEntropy :: RNG -> ByteString -> IO ()
rngAddEntropy rng bytes = withRNG rng $ \ botanRNG -> do
    withPtr bytes $ \ bytesPtr -> do
        throwBotanIfNegative_ $ botan_rng_add_entropy botanRNG (ConstPtr bytesPtr) (fromIntegral $ ByteString.length bytes)

systemRNG :: RNG
systemRNG = unsafePerformIO $ rngInit System
{-# NOINLINE systemRNG #-}

userThreadsafeRNG :: RNG
userThreadsafeRNG = unsafePerformIO $ rngInit UserThreadsafe
{-# NOINLINE userThreadsafeRNG #-}

userThreadsafeRNGGet :: Int -> IO ByteString
userThreadsafeRNGGet = rngGet userThreadsafeRNG

{-
RNG types
-}

data RNGType
    = System
    | User
    | UserThreadsafe
    -- | Autoseeded -- is / was one of the two above, which may be the same thing now
    | RDRand

rngTypeName :: RNGType -> ByteString
rngTypeName System         = BOTAN_RNG_TYPE_SYSTEM
rngTypeName User           = BOTAN_RNG_TYPE_USER
rngTypeName UserThreadsafe = BOTAN_RNG_TYPE_USER_THREADSAFE
rngTypeName RDRand         = BOTAN_RNG_TYPE_RDRAND

