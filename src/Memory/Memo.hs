{-# LANGUAGE CPP #-}

module Memory.Memo where

import Memory.Prelude

import qualified Foreign.Storable as Foreign
import qualified Foreign.ForeignPtr as ForeignPtr
#if defined(USE_BYTESTRING)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Internal as ByteString
#endif

class Memory (memo :: Type -> Type) where
    type Memorable memo a :: Constraint
    type Memorable memo a = ()
    -- NOTE: Shape is roughly the same thing as Allocator.Layout
    -- and it may be merged if there are no impediments or else constraints may
    -- be introduced to relate them - see ancillary classes for usage
    -- type Shape memo :: *

instance Memory Ptr where
    type Memorable Ptr a = Foreign.Storable a

instance Memory ForeignPtr where
    type Memorable ForeignPtr a = Foreign.Storable a

instance Memory IORef where
instance Memory (IOArray i) where

-- Alternative names: Memorandum, or WithMemo / WithMemory
class (Memory (Memo mem)) => Memorized mem where
    type Memo mem :: Type -> Type
    type MemRep mem :: Type
    withMemo :: mem -> (Memo mem (MemRep mem) -> IO a) -> IO a

-- NOTE: Pointers are self-memos
instance Memorized (Ptr a) where
    type Memo (Ptr a) = Ptr
    type MemRep (Ptr a) = a
    withMemo ptr action = action ptr

instance Memorized (ForeignPtr a) where
    type Memo (ForeignPtr a) = Ptr
    type MemRep (ForeignPtr a) = a
    withMemo ptr action = ForeignPtr.withForeignPtr ptr action

#if defined(USE_BYTESTRING)
instance Memorized ByteString where
    type Memo   ByteString = ForeignPtr
    type MemRep ByteString = Word8
    withMemo bs action = do
        let (fptr,_) = ByteString.toForeignPtr0 bs
        action (ForeignPtr.castForeignPtr fptr)
#endif

class (Memory memo, Memorized mem) => WithMemory memo mem where
    withMemory :: mem -> (memo (MemRep mem) -> IO a) -> IO a

-- NOTE: We get instances for free by moving the default implementation here
instance {-# OVERLAPPABLE #-} (Memory memo, Memorized mem, Memo mem ~ memo) => WithMemory memo mem where
    withMemory = withMemo

#if defined(USE_BYTESTRING)
    
instance WithMemory Ptr ByteString where
    withMemory ptr action = withMemo ptr $ \ fPtr -> withMemo fPtr action

-- NOTE: The overlappable instance provides this automatically
-- If we move the default into the class, we do have to declare it
-- instance WithMemory ForeignPtr ByteString where
    
#endif

type WithPtr mem = WithMemory Ptr mem

withPtr :: WithPtr mem => mem -> (Ptr (MemRep mem) -> IO a) -> IO a
withPtr = withMemory

type WithForeignPtr mem = WithMemory ForeignPtr mem

withForeignPtr :: WithForeignPtr mem => mem -> (ForeignPtr (MemRep mem) -> IO a) -> IO a
withForeignPtr = withMemory
