{-# LANGUAGE RoleAnnotations #-}

module Memory.Memo.Pointer.State where

import Memory.Prelude

import qualified Foreign.Ptr as Ptr
import qualified Foreign.Storable as Foreign
import qualified Foreign.Marshal.Alloc as Foreign

{-
This is a simple state token similar to:
- IORef a and RealWorld
- STRef s a
- MutVar# s a
- vector:MutableArray s a
We could probably call it STPtr, and have the original Ptr mean an immutable ptr
-}
type role StatePtr nominal representational
newtype StatePtr s a = MkStatePtr (Ptr a)

unsafeGetStatePtr :: StatePtr s a -> Ptr a
unsafeGetStatePtr (MkStatePtr ptr) = ptr

peekStatePtr :: (Foreign.Storable a) => StatePtr s a -> IO a
peekStatePtr (MkStatePtr ptr) = Foreign.peek ptr

pokeStatePtr :: (Foreign.Storable a) => StatePtr s a -> a -> IO ()
pokeStatePtr (MkStatePtr ptr) = Foreign.poke ptr

castStatePtr :: StatePtr s a -> StatePtr s b
castStatePtr (MkStatePtr ptr) = MkStatePtr (Ptr.castPtr ptr)

withStatePtr :: StatePtr s a -> (Ptr a -> IO b) -> IO b
withStatePtr (MkStatePtr ptr) action = action ptr

-- TODO: Instances

{- Eg:
type IOPtr = StatePtr RealWorld
-}

-- NOTE: These could be bound to an allocator class but its easier to just make
-- these ones into functions due to their temporary block-scoped nature

-- NOTE: Of course you can still return the raw inner pointer but its nice that
-- the type system warns you (and the respective function IS called
-- unsafeGetStatePtr which is a rather large clue)

withTempPtr :: (Foreign.Storable a) => (forall s . StatePtr s a -> IO b) -> IO b
withTempPtr f = Foreign.alloca (\ ptr -> f (MkStatePtr ptr))

withTempBytes :: Int -> (forall s . StatePtr s a -> IO b) -> IO b
withTempBytes sz f = Foreign.allocaBytes sz (\ ptr -> f (MkStatePtr ptr))

withTempBytesAligned :: Int -> Int -> (forall s . StatePtr s a -> IO b) -> IO b
withTempBytesAligned sz al f = Foreign.allocaBytesAligned sz al (\ ptr -> f (MkStatePtr ptr))

-- TODO: A TempByteString Allocator

{-
:{
ptr <- withTempPtr $ \ (ptr :: StatePtr s Word64) -> do
    pokeStatePtr ptr 1024
    x <- peekStatePtr ptr
    putStrLn $ show x
    pure $ unsafeGetStatePtr ptr
x <- peek ptr
putStrLn $ show x
:}
-}

-- We could also do thread-local pointers and such