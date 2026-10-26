{-# LANGUAGE OverloadedStrings #-}

module Botan.Internal.String
(   prn
,   commas
,   slashes
,   slash
,   parens
,   (//)
,   (/$)
) where

import Data.Semigroup
import Data.Foldable (foldl')
import Data.String (IsString (..))
import qualified Data.List as List (intersperse)
import qualified GHC.Show as Show (Show (show))

-- NOTE: 
-- prepends :: (Semigroup s, IsString s) => s -> [s] -> [s]
-- prepends _ [] = []
-- prepends sep (x:xs) = sep : x : prepends sep xs

intersperse :: (Semigroup s, IsString s) => s -> [s] -> [s]
-- intersperse _   []    = []
-- intersperse sep items = List.intersperse sep items
intersperse = List.intersperse

intercalate :: (Semigroup s, IsString s) => s -> [s] -> s
intercalate _ [] = ""
intercalate sep (x:xs) = foldl' (\ acc i -> acc <> sep <> i) x xs

-- AKA generic show, from relude, maybe call sprn so prn can be putStrLn
prn :: forall b a . (Show.Show a, IsString b) => a -> b
prn x = fromString (Show.show x)

commas :: (IsString a, Semigroup a) => [a] -> a
commas = intercalate ","

slashes :: (IsString a, Semigroup a) => [a] -> a
slashes = intercalate "/"

-- Builders as infix words as a base for legibility

infixr 6 `slash`
slash :: (IsString a, Semigroup a) => a -> a -> a
a `slash` b = a <> "/" <> b

infixr 0 `parens`
parens :: (IsString a, Semigroup a) => a -> a -> a
a `parens` b = a <> "(" <> b <> ")"

-- Optional operators for saving space

infixr 6 //
(//) :: (IsString a, Semigroup a) => a -> a -> a
(//) = slash

infixr 0 /$
(/$) :: (IsString a, Semigroup a) => a -> a -> a
(/$) = parens
