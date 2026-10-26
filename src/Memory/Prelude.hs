{-# LANGUAGE CPP #-}
module Memory.Prelude
(   module Prelude
,   module Data.Kind
,   module Data.Type.Bool
,   module Data.Type.Equality
,   module Data.Type.Ord
,   module Data.Proxy
,   module Data.Int
,   module Data.Word
,   module GHC.Exts
,   module GHC.TypeLits
,   module Foreign.Ptr
,   module Foreign.ForeignPtr
,   module Data.IORef
,   module GHC.IOArray
#if defined(USE_BYTESTRING)
,   module Data.ByteString
#endif
) where

import Prelude hiding (not, and, or, Ordering)
import Data.Kind
import Data.Type.Bool
import Data.Type.Equality
import Data.Type.Ord
import Data.Proxy
import Data.Int (Int8, Int16, Int32, Int64)
import Data.Word (Word8, Word16, Word32, Word64)
import GHC.Exts (RealWorld)
import GHC.TypeLits
import Foreign.Ptr (Ptr, FunPtr)
import Foreign.ForeignPtr (ForeignPtr, FinalizerPtr)
import Data.IORef (IORef)
import GHC.IOArray (IOArray)
#if defined(USE_BYTESTRING)
import Data.ByteString (ByteString)
#endif

{-
This library sits beneath another theoretical library that we will call 'logic'.

Roughly speaking:

class LogicalFramework x where
    type LogicType x
    type LogicalUnit x

class MemoryFramework x where
    type StorageUnit x -- Or storagetype
    type AddressableUnit x

instance LF Classical where
    type LT = Boolean
    type LU = Bool

instance LF Numeric where
    type LT = Arithmetic
    type LU = Number

instance MF Digital where
    type SU = Digit
    type AU = Word

instance MF Binary where
    type SU = Bit
    type AU = Bit

This library only concerns itself with classical numeric logic with digital
binary storage, meaning the base storage unit is bit, but the base addressable
unit is left open. Numeric logic means that the interpreted type can be boolean,
integer, or floating point.

-}
