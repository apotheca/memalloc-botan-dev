module Memory.Sandbox where

import Memory.Prelude

import qualified Foreign.Storable as Foreign
import qualified Foreign.ForeignPtr as ForeignPtr


-- Ancillary classes for memos / memories
-- Maybe move to Memory.Memo.Methods
-- NOTE: Needs instances, fixing, integration

{-
class (Memory mem) => MemComparable mem where
    memCompare :: (Ord a) => mem a -> mem a -> Shape mem -> IO Ordering
    memEq :: (Ord a) => mem a -> mem a -> Shape mem -> IO Bool

class (MemComparable mem) => MemConstComparable mem where
    memConstCompare :: (Ord a) => mem a -> mem a -> Shape mem -> IO Ordering
    memConstEq :: (Ord a) => mem a -> mem a -> Shape mem -> IO Bool

class (Memory mem) => MemCopyable mem where
    memCopy :: mem a -> Shape mem -> mem a -> IO ()

-- I like MemMutable instead, where memSet mem a sh = memMut mem (const a) sh
class (Memory mem) => MemSettable mem where
    memSet :: mem a -> a -> Shape mem -> IO ()

-- Basic memory functors
-- NOTE: Maybe this should be Mappable / Reducible / Visitable

class (Memory mem) => MemFunctor mem where
    memMapCopy :: (a -> b) -> mem a -> Shape mem -> mem b -> IO ()
    memMapAlloc :: (a -> b) -> mem a -> Shape mem -> IO (mem b)
    memMapMutate :: (a -> a) -> mem a -> Shape mem -> IO ()

class (Memory mem) => MemFoldable mem where
    memFoldl :: (b -> a -> b) -> b -> mem a -> Shape mem -> IO b
    memFoldr :: (a -> b -> b) -> b -> mem a -> Shape mem -> IO b
    memFoldMap :: Monoid m => (a -> m) -> mem a -> Shape mem -> IO m

class (MemFunctor mem) => MemZipFunctor mem where
    memZipWithCopy :: (a -> b -> c) -> mem a -> mem b -> mem c -> Shape mem -> IO ()
-}

{-
Partial orders - clean up and move to Memory.Order
-}


class Eq a => PreOrd a where
    leq :: a -> a -> Bool
    geq :: a -> a -> Bool

class PreOrd a => PartialOrd a where
    lt :: a -> a -> Bool
    gt :: a -> a -> Bool
    comparable :: a -> a -> Bool

class (PreOrd a, Eq a) => PartialEq a where
    peq :: a -> a -> Bool
    pneq :: a -> a -> Bool

class PartialEq a => Equivalence a

class PreOrd a => TotalPreOrd a

class (PartialOrd a, TotalPreOrd a) => TotalOrd a

class Eq a => StrictPreOrd a where
    slt :: a -> a -> Bool

class StrictPreOrd a => StrictPartialOrd a

class StrictPartialOrd a => StrictTotalOrd a
