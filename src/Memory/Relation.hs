{-# LANGUAGE UndecidableInstances #-}

module Memory.Relation where

import Memory.Prelude

import qualified Prelude

{-
Partial and total equivalence classes, named so to avoid conflict with Prelude

These classes are necessary for the injection of the Address class underneath
the Ix class (now named Index).

See this illustrated category theory primer on orders:
- https://abuseofnotation.github.io/category-theory-illustrated/04_order/

Properties:

- Transitive    - if x R y and y R z, then x R z
- Reflexive     - x R x is always true
- Irreflexive   - x R x is never true
- Symmetric     - if x R y then y R x
- Total         - either x R y or y R x or both (weak is either, strong is either or both)
- Antisymmetric - if x R y and y R x then x == y

We can imagine PartialEq, PreOrd, and StrictPreOrd as all being a subclass of
some 'Relation' class with the property of transitivity, but thats overkill for
the moment

NOTE: PartialEquality and TotalEquality are defined as Maybe type aliases
but PartialOrder and TotalOrder are unique types - probably should embrace the
Maybe and use pattern synonyms for PEQ / TEQ / etc
-}

{-
Equivalence relations (==)
-}

{-
A transitive relation that is also symmetric:
- Transitive
- Symmetric
-}
class PartialEq a where

    peq  :: a -> a -> PartialEquality
    pneq :: a -> a -> PartialEquality
    
    default pneq :: (TotalEq a) => a -> a -> PartialEquality
    pneq x y = fmap Prelude.not (peq x y)

    -- Like comparable, but only for equivalence and not order
    -- Maybe compatible? equitable? relatable?
    -- Returns true if not incomparable
    equitable :: a -> a -> Bool

    equitable x y = case peq x y of
        Nothing -> False
        _       -> True

type PartialEquality = Maybe Bool

{-
A partial equivalence that is also reflexive:
- Transitive
- Symmetric
- Reflexive
-}
class (PartialEq a) => TotalEq a where

    -- Alternatively, teq and tneq
    eq  :: a -> a -> TotalEquality
    neq :: a -> a -> TotalEquality

    neq x y = Prelude.not (eq x y)


type TotalEquality = Bool

{-
Order relations (<=)
-}

{-
A transitive relation that is also reflexive
- Transitive
- Reflexive
-}
class PreOrd a where

    leq :: a -> a -> Bool
    geq :: a -> a -> Bool
    
    leq x y = geq y x
    geq x y = leq y x

{-
A pre-order relation that is also total
- Transitive
- Reflexive
- Total
-}
class (PreOrd a) => TotalPreOrd a where
    -- No new functions, just new properties

{-
A pre-order relation that is also antisymmetric
- Transitive
- Reflexive
- Antisymmetric
-}
class (PreOrd a, PartialEq a) => PartialOrd a where
    pcompare :: a -> a -> PartialOrder
    comparable :: a -> a -> Bool

    pcompare x y
        | peq x y == Just True = PEQ
        | leq x y              = PLT
        | geq x y              = PGT
        | otherwise            = PNC

    comparable x y = case pcompare x y of
        PNC -> False
        _ -> True

-- TODO: Conversion between PartialOrder and Maybe Ordering
-- I think I prefer 
data PartialOrder
    = PLT
    | PEQ
    | PGT
    | PNC
    deriving (Show, Eq)

{-
A partial order that is also a total pre-order
-}
class (TotalPreOrd a, PartialOrd a, TotalEq a) => TotalOrd a where
    compare :: a -> a -> TotalOrder
    compare x y
        | eq x y    = TEQ
        | leq x y   = TLT
        | otherwise = TGT

-- TODO: Conversion between TotalOrder and Prelude.Ordering
data TotalOrder
    = TLT
    | TEQ
    | TGT
    deriving (Show, Eq)

-- NOTE: Need some sort of bit matrix for eg:
-- - Eq, Neq, Inc, Lt, Gt, Lte, Gte

{-
Preference relations (<)
-}

{-
A transitive relation that is also irreflexive
- Transitive
- Irreflexive
- Asymmetric becaues irreflexive plus transitive implies
-}
class StrictPreOrd a where

    lt :: a -> a -> Bool
    gt :: a -> a -> Bool
    
    lt x y = gt y x
    gt x y = lt y x

{-
A strict pre-order that has transitivity of incomparability
- Incomparability - if a INC b and b INC c, then a INC c
-}
class (StrictPreOrd a) => StrictTotalPreOrd a where

{-
A strict pre order with partial equivalence.
-}
class (StrictPreOrd a, PartialEq a) => StrictPartialOrd a where

    -- Strict leq
    sleq :: a -> a -> Bool
    -- Strict geq
    sgeq :: a -> a -> Bool

    sleq x y = lt x y || peq x y == Just True
    sgeq x y = gt x y || peq x y == Just True

{-
- Trichotomous (either x < y, x > y, or x == y)
-}
class (StrictTotalPreOrd a, StrictPartialOrd a, TotalEq a) => StrictTotalOrd a where

    -- Strict compare
    scompare :: a -> a -> TotalOrder
    scompare x y
        | lt x y    = TLT
        | gt x y    = TGT
        | otherwise = TEQ

{-
Useful definitions - requires undecidable instances, may require overlappable too
NOTE: These interfere with default instances from Eq, Ord - not unexpected,
there are many alternative paths
-}

{-
instance (StrictTotalOrd a) => PreOrd a where
    leq = sleq
    geq = sgeq

instance (StrictTotalOrd a) => TotalPreOrd a

instance (StrictTotalOrd a, PartialEq a) => PartialOrd a where
    pcompare x y = case scompare x y of
        TLT -> PLT
        TEQ -> PEQ
        TGT -> PGT
    comparable _ _ = True

instance (StrictTotalOrd a, TotalEq a) => TotalOrd a where
    compare = scompare
-}

{-
Instances for prelude Eq and Ord
Its either this or force people to use a DerivingVia
Yeah I think I prefer that
-}

{-
instance (Prelude.Eq a) => PartialEq a where
    peq x y = Just (x Prelude.== y)
    equitable _ _ = True

instance (Prelude.Eq a) => TotalEq a where
    eq = (Prelude.==)

instance (Prelude.Ord a, Prelude.Eq a) => PreOrd a where
    leq = (Prelude.<=)
    geq = (Prelude.>=)

instance (Prelude.Ord a, Prelude.Eq a) => TotalPreOrd a

instance (Prelude.Ord a, Prelude.Eq a) => StrictPreOrd a where
    lt = (Prelude.<)
    gt = (Prelude.>)

instance (Prelude.Ord a, Prelude.Eq a) => StrictTotalPreOrd a

instance (Prelude.Ord a, Prelude.Eq a) => StrictPartialOrd a

instance (Prelude.Ord a, Prelude.Eq a) => StrictTotalOrd a where
    scompare x y = case Prelude.compare x y of
        Prelude.LT -> TLT
        Prelude.EQ -> TEQ
        Prelude.GT -> TGT
-}
