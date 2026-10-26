module Memory.Allocator where

import Memory.Prelude
import Memory.Memo

-- NOTE: Need the default implementation of alloc-init again
class (Memorized (Allocation alr)) => Allocator alr where

    type family Layout alr :: Type
    type family Allocation alr :: Type

    alloc :: alr -> Layout alr -> IO (Allocation alr)
    alloc alr lay = allocInit alr lay (const (pure ()))

    allocInit
        :: alr
        -> Layout alr
        -> (Memo (Allocation alr) (MemRep (Allocation alr)) -> IO ())
        -> IO (Allocation alr)
    -- NOTE: Initializer instances should implement this via prealloc + init
    allocInit alr lay action = do
        aln <- alloc alr lay
        withMemo aln action
        pure aln

-- This class allows us to differentiate mutable memory from uninitialized
-- write-once immutable / read-only memory
-- NOTE: We should probably define the defaults to give us a free implementation
-- where Preallocation ~ Allocation
class (Allocator alr) => Initializer alr where

    type family Preallocation alr
    
    prealloc :: alr -> Layout alr -> IO (Preallocation alr)

    init
        :: alr
        -> Preallocation alr
        -> (Memo (Allocation alr) (MemRep (Allocation alr)) -> IO ())
        -> IO (Allocation alr)

-- TODO: Freeable typeclass for Memory that can knows its own allocator / can
-- free itself; this is useful when the allocator stores metadata in an area
-- accessible from the memo itself eg in an array of structs tag, as opposed to
-- a struct of arrays which keeps the metadata of the memo separate - this is
-- one of the ways that SoA differs from AoS - things get externalized
class (Allocator alr) => Deallocator alr where

    -- NOTE: The deallocator should not require a layout argument to free an
    -- allocation. Early versions of C required the layout / size in order to
    -- free memory, and this ended up being a source of bugs, as allocations
    -- had to be paired with their layouts. It is simply better to require that
    -- the allocator track its own allocations. We adopt this justification
    dealloc :: alr -> Allocation alr -> IO ()


class (Allocator alr) => Reallocator alr where

    realloc :: alr -> Allocation alr -> Layout alr -> IO (Allocation alr)
