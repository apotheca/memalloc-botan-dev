{-# LANGUAGE AllowAmbiguousTypes #-}

module Botan.Internal.Object
( BotanObject(..)
) where

import Botan.Bindings.ConstPtr (ConstPtr (..))
import Botan.Bindings.RNG
import Botan.Internal.Error (throwBotanIfNegative_)

import Data.ByteString (ByteString)

import Foreign.Ptr (Ptr)
import qualified Foreign.Ptr as Ptr
import qualified Foreign.Storable as Ptr

import Foreign.ForeignPtr (ForeignPtr, FinalizerPtr)
import qualified Foreign.ForeignPtr as ForeignPtr
import Foreign.C.Types (CInt)
import Foreign.Marshal.Alloc (alloca)

import Memory.Memo
import Memory.Memo.Pointer

import Data.Kind

import Control.Monad (void)
import Control.Exception (mask_)

class
    ( Memorized a
    , Memo a ~ ForeignPtr
    , MemRep a ~ BotanStruct a
    , Memorized (BotanPtr a)
    , Memo (BotanPtr a) ~ Ptr
    , MemRep (BotanPtr a) ~ BotanStruct a
    -- , Ptr.Storable (BotanPtr a) -- NOTE: Needed for peek in createBotan
    ) => BotanObject a where

    type family BotanStruct a :: Type
    type family BotanPtr    a :: Type

    toBotanPtr :: Ptr (BotanStruct a) -> BotanPtr a
    toBotan    :: ForeignPtr (BotanStruct a) -> a
    botanFinalizer :: FinalizerPtr (BotanStruct a)

    -- NOTE: With the prolific use of mask_ before eg withFoo, why not just do
    -- it here?
    withBotanPtr :: a -> (BotanPtr a -> IO b) -> IO b
    withBotanPtr botan action =
        withMemo botan $ \ fptr -> do
            withMemo fptr $ \ ptr -> do
                action (toBotanPtr @a ptr)

    createBotan :: (Ptr (BotanPtr a) -> IO CInt) -> IO a
    -- NOTE: Requires Storable instance for BotanPtr (which we have)
    -- createBotan init = mask_ $ alloca $ \ (ptrPtr :: Ptr (BotanPtr a)) -> do
    --     void {- throwBotanIfNegative_ -} $ init ptrPtr
    --     (bPtr :: BotanPtr a) <- Ptr.peek ptrPtr
    --     fptr <- withMemo bPtr $ \ ptr -> ForeignPtr.newForeignPtr (botanFinalizer @a) ptr
    --     return $ toBotan fptr
    -- But we could just cast it (knowing that it is a newtype over the pointer we want):
    createBotan init = mask_ $ alloca $ \ ptrPtr {- (ptrPtr :: Ptr (Ptr (BotanStruct a))) -} -> do
        throwBotanIfNegative_ {- void -} $ init (Ptr.castPtr ptrPtr)
        ptr {- (ptr :: Ptr (BotanStruct a)) -} <- Ptr.peek ptrPtr
        fptr <- ForeignPtr.newForeignPtr (botanFinalizer @a) ptr
        return $ toBotan fptr
    -- NOTE: Ideally, we'd want to do:
    --  withMemo ptrPtr $ \ ptr -> ... $ init (toBotanPtr @a ptr)
    -- But we cant withMemo a ptrPtr yet because Ptr.withMemo is still id

    destroyBotan :: a -> IO ()
    destroyBotan botan = withMemo botan ForeignPtr.finalizeForeignPtr
