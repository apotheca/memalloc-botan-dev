{-# LANGUAGE AllowAmbiguousTypes #-}

module Memory.Memo.Object where

import Memory.Prelude
import Memory.Memo

import Control.Exception (mask_)

import qualified Foreign.ForeignPtr as ForeignPtr
import qualified Foreign.Marshal.Alloc as Alloc
import qualified Foreign.Ptr as Ptr
import qualified Foreign.Storable as Storable

-- NOTE: Assumes we're getting a `ptr (ptr struct)`
class
    ( Memorized a
    , Memo a ~ ForeignPtr
    , MemRep a ~ ObjectStruct a
    , Memorized (ObjectPtr a)
    , Memo (ObjectPtr a) ~ Ptr
    , MemRep (ObjectPtr a) ~ ObjectStruct a
    ) => Object a where

    -- Expected to be something like:
    -- data {-# CTYPE "lib/ffi.h" "struct some_opaque_struct" #-} SomeOpaqueStruct
    type family ObjectStruct a :: Type

    -- Usually is just a (newtype over) Ptr (ObjectStruct a)
    type family ObjectPtr a :: Type
    -- This needs UndecidableInstances and I'm sort of eh on that just yet
    -- type ObjectPtr a = Ptr (ObjectStruct a)

    toObjectPtr :: Ptr (ObjectStruct a) -> ObjectPtr a
    toObject    :: ForeignPtr (ObjectStruct a) -> a

    objectFinalizer :: FinalizerPtr (ObjectStruct a)

    withObjectPtr :: forall a b. Object a => a -> (ObjectPtr a -> IO b) -> IO b
    withObjectPtr obj action =
        withMemo obj $ \ fptr ->
            withMemo fptr $ \ ptr ->
                action (toObjectPtr @a ptr)

    createObject :: (Ptr (ObjectPtr a) -> IO ()) -> IO a
    createObject = createObjectUnsafeCast

    destroyObject :: a -> IO ()
    destroyObject obj = withMemo obj ForeignPtr.finalizeForeignPtr

createObjectStorable :: forall a . (Object a, Storable.Storable (ObjectPtr a)) => (Ptr (ObjectPtr a) -> IO ()) -> IO a
createObjectStorable initialize = mask_ $ Alloc.alloca $ \ (ptrPtr :: Ptr (ObjectPtr a)) -> do
    initialize ptrPtr
    objPtr <- Storable.peek ptrPtr
    fptr <- withMemo objPtr $ \ ptr -> ForeignPtr.newForeignPtr (objectFinalizer @a) ptr
    return $ toObject fptr

-- NOTE: Unsafe casts the `ptr (ptr struct)` to a `ptr (objptr struct)`
-- Doesn't need a Storable / Memorable instance for ObjectPtr
createObjectUnsafeCast :: forall a. Object a => (Ptr (ObjectPtr a) -> IO ()) -> IO a
createObjectUnsafeCast initialize = mask_ $ Alloc.alloca $ \ ptrPtr -> do
    initialize (Ptr.castPtr ptrPtr)
    ptr <- Storable.peek ptrPtr
    fptr <- ForeignPtr.newForeignPtr (objectFinalizer @a) ptr
    return $ toObject fptr
