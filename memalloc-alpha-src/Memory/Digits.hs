module Memory.Digits where

import Memory.Prelude

import Memory.Word (Bit)

-- type family Cell arch

-- type instance Cell Classical          = Bit -- Byte
-- type instance Cell Quantum            = Qubit
-- type instance Cell Analog             = Signal
-- type instance Cell Simd               = Float4x16

-- TODO: Digitwise / digit shifting

-- Could also be Word, or Granular and grains, or Discrete
-- NOTE: There is no 'sample(Digit) :: Int -> ds -> d' - that belongs elsewhere - eg wordAt
class Digits ds d where

    fillDigits :: d -> ds -- generalies zeroBits, oneBits

    digit :: Int -> d -> ds
    setDigit :: Int -> d -> ds -> ds -- generalies setBit, clearBit
    mapDigit :: (d -> d) -> Int -> ds -> ds -- generalizes setBit, clearBit, complementBit
    testDigit :: (d -> Bool) -> Int -> ds -> d

    digitCountMaybe :: ds -> Proxy d -> Maybe Int -- generalizes bitCountMaybe

-- NOTE: queries taking a sample digit to match against can be generalized to predicates
class (Digits ds d) => FiniteDigits ds d where
    digitCount :: ds -> Proxy d -> Int -- generalizes bitcount
    popCountDigit :: (d -> Bool) -> ds -> Int -- generalizes popcount
    countTrailingDigits :: (d -> Bool) -> ds -> Int
    lowestMatchingDigit :: (d -> Bool) -> ds -> Maybe Int
    
-- TODO: Connect Word up to this here somewhere
class (FiniteDigits ds d) => FixedDigits ds d where
    digitWidth :: Proxy ds -> Proxy d -> Int
    countLeadingDigits :: (d -> Bool) -> ds -> Int
    highestMatchingDigit :: (d -> Bool) -> ds -> Maybe Int
