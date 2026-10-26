module Memory.Allocator.C where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

import Foreign.C.Types

foreign import ccall unsafe "stdlib.h malloc"
    c_malloc  ::          CSize -> IO (Ptr a)
foreign import ccall unsafe "stdlib.h realloc"
    c_realloc :: Ptr a -> CSize -> IO (Ptr a)
foreign import ccall unsafe "stdlib.h free"
    c_free    :: Ptr a -> IO ()
foreign import ccall unsafe "stdlib.h &free"
    c_finalizerFree :: FinalizerPtr a

data CAllocator = CAllocator

instance Allocator CAllocator where

    type Layout CAllocator = CSize
    type Allocation CAllocator = Ptr Word8

    alloc _ = c_malloc 

instance Deallocator CAllocator where

    dealloc _ = c_free

instance Reallocator CAllocator where

    realloc _ = c_realloc
