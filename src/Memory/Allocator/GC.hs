module Memory.Allocator.GC where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

import qualified Foreign.ForeignPtr as ForeignPtr
import qualified Foreign.Marshal.Alloc as ForeignPtr

data GCAllocator = GCAllocator

instance Allocator GCAllocator where

    type Layout GCAllocator = Int
    type Allocation GCAllocator = ForeignPtr Word8

    alloc :: GCAllocator -> Int -> IO (ForeignPtr Word8)
    alloc _ = ForeignPtr.mallocForeignPtrBytes
    -- NOTE: Could use GHC.ForeignPtr.mallocPlainForeignPtrBytes for an even
    -- faster, no-finalizer allocator but nah, the finalizers will be useful for
    -- integrating.

instance Deallocator GCAllocator where
    dealloc _ = ForeignPtr.finalizeForeignPtr

-- TODO: Use Foreign.Concurrent.newForeignPtr to add `IO ()` finalizers
-- This is much slower than mallocForeignPtrBytes or mallocPlainForeignPtrBytes
-- so should be reserved for hefty resources. It also doesn't guarantee that the
-- finalizer will actually run unless triggered manually.
-- "There is no guarantee of promptness, [..] no guarantee [that it will] run at
-- all for GC-triggered finalization." -- Foreign.Concurrent
