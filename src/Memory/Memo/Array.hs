module Memory.Memo.Array where

import Memory.Prelude
import Memory.Memo

import Data.Ix

-- TODO: Re-work this to be more like IOArray - we can avoid specific address
-- types, makes it more flexible

-- NOTE: Call it multiref for now, since Array is overloaded?
-- Nah, this *is* memarray, minus memfunctor and memfoldable.
class (Memory arr, Ix (Index arr)) => Array arr where
    type family Index arr :: Type
    type Index arr = Int
    loadAt :: arr a -> Index arr -> IO a -- Or just 'at'?
    count :: arr a -> Index arr
    -- Formerly 'index' but that competes with array:Array and Idx 'index'

class (Array arr) => MutableArray arr where
    storeAt :: arr a -> Index arr -> a -> IO ()
    updateAt :: arr a -> Index arr -> (a -> a) -> IO ()
    mutateAt :: arr a -> Index arr -> (a -> IO a) -> IO ()


{- NOTE: We could split this into MultiReference and Countable
class (Memory arr {- or Reference arr -}, Ix (Index arr)) => MultiReference arr where
    type family Index arr :: Type
    type Index arr = Int
    loadAt :: arr a -> Index arr -> IO a

-- Just Memory because Pointer might be countable
class (Memory arr) => Countable arr where
    count :: arr a -> Index arr

class (MultiReference arr, Countable arr) => Array arr where
-}