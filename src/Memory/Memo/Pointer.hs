module Memory.Memo.Pointer where

import Memory.Prelude
import Memory.Memo

import qualified Foreign.Ptr as Ptr
import qualified Foreign.ForeignPtr as ForeignPtr
import qualified Data.ByteString.Internal as ForeignPtr (nullForeignPtr)

class (Memory ptr) => Pointer ptr where
    nullPtr :: ptr a
    plusPtr :: ptr a -> Int -> ptr a
    succPtr :: ptr a -> ptr a
    succPtr p = plusPtr p 1

instance Pointer Ptr where
    nullPtr = Ptr.nullPtr
    plusPtr = Ptr.plusPtr
    succPtr p = Ptr.plusPtr p 1

instance Pointer ForeignPtr where
    nullPtr = ForeignPtr.castForeignPtr ForeignPtr.nullForeignPtr
    plusPtr = ForeignPtr.plusForeignPtr
    succPtr p = ForeignPtr.plusForeignPtr p 1

-- TODO: Really, UnsignedAddressPointer or HostAddressPointer
-- TODO: SignedAddressPointer
-- TODO: Should also have a Memory.Address constraint on the underlying address type
-- class (Pointer ptr) => UIntPointer ptr where
--     uintPtr :: ptr a -> Word
--     ptrFromUInt :: Word -> ptr a
--     alignUpPtr :: ptr a -> Int -> ptr a
--     diffPtr :: ptr a -> ptr a -> Int

-- TODO:
-- class (UIntPointer ptr) => TaggedPointer ptr where
--     data family Tag ptr :: * -> *
--     ptrTag :: ptr a -> Tag ptr a
--     untaggedAddr :: ptr a -> Address asp

-- type HostPtr a = Ptr_ a

-- class (Memorable mem, Pointer (Mem mem)) => WithPtr mem where
--     withPtr :: mem -> (Mem mem (MemRep mem) -> IO a) -> IO a
--     withPtr = withMem