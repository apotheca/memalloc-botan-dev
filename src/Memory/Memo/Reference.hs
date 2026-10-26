module Memory.Memo.Reference where

import Memory.Prelude
import Memory.Memo

import qualified Foreign.Storable as Ptr
import qualified Foreign.Ptr as Ptr
import qualified Foreign.ForeignPtr as ForeignPtr
import qualified Data.IORef as IORef

class (Memory ref) => Reference ref where

    load :: (Memorable ref a) => ref a -> IO a

instance Reference Ptr.Ptr where
    load = Ptr.peek

instance Reference ForeignPtr.ForeignPtr where
    load fptr = ForeignPtr.withForeignPtr fptr Ptr.peek

instance Reference IORef.IORef where
    load = IORef.readIORef

class (Reference ref) => MutableReference ref where

    store :: (Memorable ref a) => ref a -> a -> IO ()

    update :: (Memorable ref a) => ref a -> (a -> a) -> IO ()
    update ref f = mutate ref (return . f)

    mutate :: (Memorable ref a) => ref a -> (a -> IO a) -> IO ()
    mutate ref f = load ref >>= f >>= store ref

instance MutableReference Ptr.Ptr where
    store = Ptr.poke

instance MutableReference ForeignPtr.ForeignPtr where
    store fptr val = ForeignPtr.withForeignPtr fptr (`Ptr.poke` val)

instance MutableReference IORef.IORef where
    store = IORef.writeIORef
