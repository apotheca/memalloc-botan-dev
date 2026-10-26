module Memory.Lattice.Operator where

import Memory.Prelude
import Memory.Lattice

(/\) :: (MeetSemilattice a) => a -> a -> a
(/\) = meet

infixr 6 /\

(\/) :: (JoinSemilattice a) => a -> a -> a
(\/) = join

infixr 5 \/
