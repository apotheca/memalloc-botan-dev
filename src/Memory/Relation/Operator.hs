module Memory.Relation.Operator where

import Memory.Prelude
import Memory.Relation
import qualified Prelude

(==) :: (TotalEq a) => a -> a -> Bool
(==) = eq

infix 4 ==

(/=) :: (TotalEq a) => a -> a -> Bool
(/=) = neq

infix 4 /=

(==?) :: (PartialEq a) => a -> a -> PartialEquality
(==?) = peq

infix 4 ==?

(/=?) :: (PartialEq a) => a -> a -> PartialEquality
(/=?) = pneq

infix 4 /=?

(<=) :: (PreOrd a) => a -> a -> Bool
(<=) = leq

infix 4 <=

(>=) :: (PreOrd a) => a -> a -> Bool
(>=) = geq

infix 4 >=

(<?) :: (PartialOrd a) => a -> a -> Bool
x <? y = case pcompare x y of
    PLT -> True
    _   -> False

infix 4 <?

(>?) :: (PartialOrd a) => a -> a -> Bool
x >? y = case pcompare x y of
    PGT -> True
    _   -> False

infix 4 >?

(<=?) :: (PartialOrd a) => a -> a -> Bool
x <=? y = case pcompare x y of
    PLT -> True
    PEQ -> True
    _   -> False

infix 4 <=?

(>=?) :: (PartialOrd a) => a -> a -> Bool
x >=? y = case pcompare x y of
    PGT -> True
    PEQ -> True
    _   -> False

infix 4 >=?

(<!) :: (StrictPreOrd a) => a -> a -> Bool
(<!) = lt

infix 4 <!

(>!) :: (StrictPreOrd a) => a -> a -> Bool
(>!) = gt

infix 4 >!
