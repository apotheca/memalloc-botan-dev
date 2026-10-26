module Memory.Lattice where

import Memory.Prelude
import Memory.Relation
import Memory.Relation

{-
NOTE: I probably ought to split this into:
- class Top a where top :: a
- class Bottom a where bottom :: a
- class (Top a, Bottom a) => Bounded a where minBound = bottom, maxBound = top
- Then this needs to be restructured a bit but its fine for now
-}

class (PartialOrd a) => MeetSemilattice a where

    meet :: a -> a -> a

    default meet :: (Ord a) => a -> a -> a
    meet = min

class (PartialOrd a) => JoinSemilattice a where

    join :: a -> a -> a

    default join :: (Ord a) => a -> a -> a
    join = max

type Lattice a = (MeetSemilattice a, JoinSemilattice a)

-- NOTE: This is where Bottom in Haskell comes from
class (MeetSemilattice a) => BoundedMeetSemilattice a where

    top :: a
    default top :: (Bounded a) => a
    top = maxBound

type UpperBoundedLattice a = (BoundedMeetSemilattice a, Lattice a)

class (JoinSemilattice a) => BoundedJoinSemilattice a where

    bottom :: a
    default bottom :: (Bounded a) => a
    bottom = minBound
    
type LowerBoundedLattice a = (BoundedJoinSemilattice a, Lattice a)

-- Maybe bounded distributive lattice?
type BoundedLattice a = (LowerBoundedLattice a, UpperBoundedLattice a)

class (Lattice a) => ComplementedLattice a where
    complement :: a -> a

