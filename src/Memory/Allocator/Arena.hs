module Memory.Allocator.Arena where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

class (Allocator alr) => ArenaAllocator alr where

    deallocAll :: alr -> IO ()
