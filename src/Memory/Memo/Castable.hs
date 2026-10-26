module Memory.Memo.Castable where

import Memory.Prelude
import Memory.Memo

import qualified Foreign.Ptr as Ptr
import qualified Foreign.ForeignPtr as ForeignPtr

class (Memory mem) => Castable mem where
    cast :: mem a -> mem b

instance Castable Ptr where
    cast = Ptr.castPtr

instance Castable ForeignPtr where
    cast = ForeignPtr.castForeignPtr
