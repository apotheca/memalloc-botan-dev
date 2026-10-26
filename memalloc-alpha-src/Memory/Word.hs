module Memory.Word where

import Memory.Prelude
import Memory.Storage

import qualified Foreign.Storable as Foreign

-- NOTE: I am trying to separate collections of bits without numeric
-- interpretation (ie, Word) from Unsigned / Cardinal numbers which do have a
-- specific numeric interpretation.
-- This is probably better renamed to Memory.UInt, or Memory.Int.Unsigned, or Memory.Cardinal

data WordStorage

instance Storage WordStorage where
    type StorageTypes WordStorage = SizedWords
    type StorageFallback WordStorage n = Integer -- Really, this should be Ptr Word8 or something
    type Storable WordStorage a  = (Foreign.Storable a {- , Integral a -})

-- Cardinal
-- type U n = FindStorage n SizedWords Integer
type U n  = StorageType WordStorage n

type Bit   = U 1
type U8    = U 8
type U16   = U 16
type U32   = U 32
type U64   = U 64
