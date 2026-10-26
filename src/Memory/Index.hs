module Memory.Index where

import Memory.Prelude
import Memory.Address
import Memory.Relation

{-
Equivalent to Data.Ix, except it conforms to our hierarchy
-}
class (TotalOrd a, Address a) => Index a where

    range               :: (a,a) -> [a]
    inRange             :: (a,a) -> a -> Bool

    -- This is new
    offset         :: (a, a) -> a -> Int

    index               :: (a,a) -> a -> Int
    unsafeIndex         :: (a,a) -> a -> Int

    rangeSize           :: (a,a) -> Int
    unsafeRangeSize     :: (a,a) -> Int

    index b i
        | inRange b i = unsafeIndex b i
        | otherwise   = error "Index error."
    unsafeIndex b i = index b i

    rangeSize b@(_l,h)
        | inRange b h = unsafeIndex b h + 1
        | otherwise   = 0
    unsafeRangeSize b@(_l,h) = unsafeIndex b h + 1

-- TODO: Enum + Total Order = Address / Index