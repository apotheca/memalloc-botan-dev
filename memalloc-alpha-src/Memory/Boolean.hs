module Memory.Boolean where

import Memory.Prelude
import Memory.Lattice

-- NOTE: I have unbound the boolean class from Propositional(Logic) and
-- ComplementedLattice, but they still make good defaults.
-- NOTE: zeroes and ones are really better a part of Bitwise; Boolean doesn't
-- imply any sort of poly-arity / multiplicity / arrangement / array-ness
class (Eq a) => Boolean a where

    false :: a
    default false :: (LowerBoundedLattice a) => a
    false = bottom

    true :: a
    default true :: (UpperBoundedLattice a) => a
    true = top

    not :: a -> a
    -- Really, it's the other way around:
    -- negation = not, when boolean algebra is used in propositional logic
    -- default not :: (Logical a) => a -> a
    -- not = negation
    -- So we actually completely default to lattices
    default not :: (ComplementedLattice a) => a -> a
    not = complement
    
    and :: a -> a -> a
    default and :: (MeetSemilattice a) => a -> a -> a
    and = meet
    
    or :: a -> a -> a
    default or :: (JoinSemilattice a) => a -> a -> a
    or = join

    xor :: a -> a -> a
    xor x y = (x `or` y) `and` (not (x `and` y))

    nand :: a -> a -> a
    nand x y = not (x `and` y)

    nor :: a -> a -> a
    nor x y = not (x `or` y)

    xnor :: a -> a -> a
    xnor x y = not (x `xor` y)