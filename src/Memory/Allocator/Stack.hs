module Memory.Allocator.Stack where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

class (Allocator alr) => StackAllocator alr where

    deallocPop :: alr -> (Allocation alr -> IO a) -> IO a