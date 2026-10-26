module Memory.Allocator.IORef where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

import qualified Data.IORef as IORef

-- data IORefAllocator a = IORefAllocator

-- instance Allocator (IORefAllocator (a :: Type)) where

--     type Layout (IORefAllocator a) = a
--     type Allocation (IORefAllocator a) = IORef a

--     alloc _ = IORef.newIORef

-- I thought it was a lack of a Memorable instance (probably contributes)
-- but no...
-- instance Memorable (IORef a) where
--     type Mem (IORef a) = IORef
    -- withMem ref action = action (IORef.readIORef ref)