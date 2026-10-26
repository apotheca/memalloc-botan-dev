module Botan.Internal.Prelude
( module Memory.Memo
, module Memory.Memo.Pointer
, module Memory.Memo.Castable
, module Memory.Allocator
, module Memory.Allocator.ByteString
, module Botan.Bindings.ConstPtr
, module Control.DeepSeq
, module Control.Exception
, module Control.Monad
, module Data.Bifunctor
, module Data.ByteString
, module Data.Kind
, module Data.Maybe
, module Data.Word
, module Foreign.C.Types
, module Foreign.ForeignPtr
, module Foreign.Marshal.Alloc
, module Foreign.Ptr
, module Foreign.Storable
, module System.IO.Unsafe
, module Botan.Bindings.Error
, module Botan.Internal.String
, module Botan.Internal.Object
, module Botan.Internal.Error
, module Botan.KeySpec
, queryBufferLength
, botanObjectAction
, botanObjectName
, botanObjectKeyspec
, botanObjectStorable
, botanObjectIntegral
, PtrList(..)
, AllocaMany(..)
, withPtrLen
) where

{-
Re-exports
-}

import Memory.Memo
import Memory.Memo.Pointer
import Memory.Memo.Castable
import Memory.Allocator
import Memory.Allocator.ByteString

import Botan.Bindings.ConstPtr (ConstPtr (..))

import Control.DeepSeq (($!!))
import Control.Exception (try, mask_)
import Control.Monad

import Data.Bifunctor
import Data.ByteString (ByteString, useAsCString)
import Data.Kind
import Data.Maybe
import Data.Word (Word8, Word16, Word32, Word64)

import Foreign.C.Types (CSize, CInt, CChar)
import Foreign.ForeignPtr (ForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable(..))

import System.IO.Unsafe (unsafePerformIO)

import Botan.Bindings.Error
import Botan.Internal.String
import Botan.Internal.Object -- TODO: Move to Botan.Internal.Object
import Botan.Internal.Error
import Botan.KeySpec

{-
Prelude-internal imports
-}

import qualified Data.ByteString as ByteString

{-
Unplaced / botan-specific functions
-}

-- TODO: Emplace somewhere
queryBufferLength :: (Ptr CSize -> IO CInt) -> IO Int
queryBufferLength fn = mask_ $ alloca $ \ szPtr -> do
    poke szPtr 0
    code <- fn szPtr
    if code == BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE
        then fromIntegral <$> peek szPtr
        else throwBotanError code

botanObjectAction :: (BotanObject a) => (BotanPtr a -> IO CInt) -> a -> IO ()
botanObjectAction f obj = mask_ $ withBotanPtr obj $ \ objPtr -> do
    throwBotanIfNegative_ $ f objPtr

botanObjectName :: BotanObject a => (BotanPtr a -> Ptr CChar -> Ptr CSize -> IO CInt) -> a -> IO ByteString
botanObjectName f obj = mask_ $ withBotanPtr obj $ \ objPtr -> do
    n <- queryBufferLength $ \ szPtr -> f objPtr nullPtr szPtr
    name <- alloca $ \ szPtr -> do
        poke szPtr (fromIntegral n)
        allocInit ByteStringAllocator n $ \ fPtr -> withPtr fPtr $ \ namePtr -> do
            throwBotanIfNegative_ $ f objPtr (cast namePtr) szPtr
    -- TODO Check n vs the actual length
    return $!! ByteString.takeWhile (/= 0) name

botanObjectKeyspec :: (BotanObject a) => (BotanPtr a -> Ptr CSize -> Ptr CSize -> Ptr CSize -> IO CInt) -> a -> IO (SizeSpec b)
botanObjectKeyspec f obj = withBotanPtr obj $ \ objPtr -> do
    allocaMany @[CSize, CSize, CSize] $ \ (mn :> mx :> md :> PNil) -> do
        throwBotanIfNegative_ $ f objPtr mn mx md
        mn' <- peek mn
        mx' <- peek mx
        md' <- peek md
        return $ sizeSpec (fromIntegral mn') (fromIntegral mx') (fromIntegral md')

botanObjectStorable :: (BotanObject a, Storable int) => (BotanPtr a -> Ptr int -> IO CInt) -> a -> IO int
botanObjectStorable f obj = mask_ $ withBotanPtr obj $ \ objPtr -> do
    alloca $ \ ptr -> do
        throwBotanIfNegative_ $ f objPtr ptr
        peek ptr

botanObjectIntegral
    :: (BotanObject a, Storable int, Integral int, Integral asInt)
    => (BotanPtr a -> Ptr int -> IO CInt) -> a -> IO asInt
botanObjectIntegral f a = fromIntegral <$> botanObjectStorable f a

data PtrList (tys :: [Type]) where
    PNil :: PtrList '[]
    (:>) :: (Storable a) => Ptr a -> PtrList tys -> PtrList (a : tys)

infixr 5 :>

-- TODO:
-- class (Storable a) => Alloca a where
--     alloca_ :: (Ptr a -> IO a) -> IO a

-- NOTE: Inspired by withMany:
-- https://hackage-content.haskell.org/package/base-4.22.0.0/docs/Foreign-Marshal-Utils.html#v:withMany
class AllocaMany (tys :: [Type]) where
    allocaMany :: (PtrList tys -> IO a) -> IO a

instance AllocaMany '[] where
    allocaMany f = f PNil

instance (Storable a, AllocaMany tys) => AllocaMany (a : tys) where
    allocaMany f = alloca $ \ p -> allocaMany (\ ps -> f (p :> ps))

-- TODO: Generalize, relax Int to Integral, move to `memalloc`
withPtrLen :: ByteString -> (Ptr Word8 -> Int -> IO a) -> IO a
withPtrLen mem f = withPtr mem $ \ ptr -> f ptr (ByteString.length mem)
