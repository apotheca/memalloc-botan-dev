module Memory.Float where

import Memory.Prelude
import Memory.Storage

import qualified Foreign.Storable as Foreign

data FloatStorage
    
instance Storage FloatStorage where
    type StorageTypes FloatStorage = SizedFloats
    type Storable FloatStorage a  = (Foreign.Storable a {- , Integral a -})

-- type F n = FindStorage n SizedFloats (NoStorageError SizedFloats n)
type F n  = StorageType FloatStorage n

type F32   = F 32
type F64   = F 64
