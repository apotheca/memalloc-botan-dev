module Memory.Address where

import Memory.Prelude
import Memory.Relation

{-
A weaker version of Data.Ix that only requires partial order - thus supporting
eg concepts like segmented memory where addresses may overlap.

Addresses don't have range; instead they have layout
-}
class (PartialOrd a) => Address a where

    layout   :: (a,a) -> [a]
    inLayout :: (a,a) -> a -> Bool

    -- This is new
    distance :: a -> a -> Maybe Int

    address        :: (a,a) -> a -> Maybe Int
    unsafeAddress  :: (a,a) -> a -> Maybe Int

    layoutSize           :: (a,a) -> Int
    unsafeLayoutSize     :: (a,a) -> Int

    -- TODO: Default implementations using pcompare

-- TODO: Enum + Total Order = Address / Index


{-
TODO: Move to Memory.Address.Space?
-}

-- Unused but important conceptually - this is really similar and related to
-- both addressing of word subunits as well as the larger concepts of memory
-- paging and stuff
class (Address addr) => AddressSpace asp addr where

    -- NOTE: Different addresses can point to the same place
    -- Also called addrEq
    sameAddr :: asp -> addr -> addr -> Bool
    validAddr :: asp -> addr -> Bool

