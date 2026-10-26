module Memory.Allocator.Std where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

import qualified Foreign.Ptr as Ptr
import qualified Foreign.Marshal.Alloc as Ptr

data StdAllocator = StdAllocator

instance Allocator StdAllocator where

    type Layout StdAllocator = Int
    type Allocation StdAllocator = Ptr Word8

    -- NOTE: When we say alloc n bytes, it doesnt mean allocate a pointer to an
    -- array of n bytes, it means allocate n (pointer-to-a-byte)s
    alloc :: StdAllocator -> Int -> IO (Ptr Word8)
    alloc _ = Ptr.mallocBytes

instance Deallocator StdAllocator where
    dealloc _ = Ptr.free
    