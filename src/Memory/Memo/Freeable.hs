module Memory.Memo.Freeable where

import Memory.Prelude
import Memory.Memo

import qualified Foreign.Ptr as Ptr
import qualified Foreign.ForeignPtr as ForeignPtr

-- TODO: INSTANCES, NEEDS TO RELATE TO DEALLOCATOR / DEALLOC

class (Memory mem) => Freeable mem where
    free :: mem a -> IO ()
