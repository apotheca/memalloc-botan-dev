module Memory.Allocator.ByteString where

import Memory.Prelude
import Memory.Allocator
import Memory.Memo

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Internal as ByteString
import qualified Foreign.ForeignPtr as ForeignPtr

-- TODO: Generalize this as TypedAllocator, eg TypedAllocator ByteString or
-- maybe HasAllocator or HasTypedAllocator
data ByteStringAllocator = ByteStringAllocator

instance Allocator ByteStringAllocator where

    type Layout ByteStringAllocator = Int
    type Allocation ByteStringAllocator = ByteString

    -- NOTE: This is just ByteString.Internal.createFp but using withMem :)
    allocInit
        :: ByteStringAllocator
        -> Int
        -> (Memo ByteString a -> IO ())
        -> IO ByteString
    allocInit _ len action = do
        fptr <- ByteString.mallocByteString len
        action (ForeignPtr.castForeignPtr fptr)
        ByteString.mkDeferredByteString fptr len

instance Deallocator ByteStringAllocator where

    dealloc :: ByteStringAllocator -> ByteString -> IO ()
    dealloc _ bs = do
        let (fptr,_) = ByteString.toForeignPtr0 bs
        ForeignPtr.finalizeForeignPtr fptr

-- TODO: Reallocator instance?
