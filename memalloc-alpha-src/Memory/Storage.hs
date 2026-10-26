{-# LANGUAGE
    UndecidableInstances
-- ,   AllowAmbiguousTypes
#-}

module Memory.Storage where

import Memory.Prelude

import Memory.Memory


-- NOTE: Requires UndecideableInstances, but it is safe
type FindStorage :: Nat -> [(Nat, Type)] -> Type -> Type
type family FindStorage n types fallback where
    FindStorage n ('(limit, t) ': ts) fb = 
        If (n <=? limit) t (FindStorage n ts fb)
    FindStorage n '[] fb = fb

type SizedWords =
    [ '(8,  Word8)
    , '(16, Word16)
    , '(32, Word32)
    , '(64, Word64)
    ]

type SizedFloats = 
    [ '(32, Float)
    , '(64, Double)
    ]

type NoStorageError k n = TypeError 
    (    Text "No storage found for "
    :<>: ShowType k
    :<>: Text " for size "
    :<>: ShowType n
    :<>: Text "."
    )

-- This generalizes storable
-- TODO: Generalize from Nat to type predicates 'k -> Bool'; we need
-- defunctionalization or dependent types for that, but this is fine for now
-- Nat is essentially 'StorageLayout'
class Storage k where
    type StorageTypes k :: [(Nat, Type)]
    type StorageFallback k (n :: Nat) :: Type
    type StorageFallback k n = NoStorageError k n
    -- Original name: StorageConstraint
    type Storable k a :: Constraint
    type Storable k a = ()

type StorageType k n = FindStorage n (StorageTypes k) (StorageFallback k n)

-- Eg:
--      ghci> import Memory.Word
--      ghci> :kind! U 128
--      U 128 :: *
--      = Integer
--      ghci> u = 5 :: U 128
--      ghci> :t u
--      u :: Integer
--      ghci> import Memory.Float
--      ghci> :kind! F 128
--      F 128 :: *
--      = (TypeError ...)
--      ghci> f = 5 :: F 128
--      <interactive>:76:1: error: [GHC-47403]
--          • No storage found for FloatStorage of size 128.
--          • When checking the inferred type
--              f :: (TypeError ...)

-- TODO: Actual type-level predicate storage instead of just querying based on
-- size, eg so we could use:
type family FitsInBits (limit :: Nat) (n :: Nat) :: Bool where
    FitsInBits limit n = n <=? limit
