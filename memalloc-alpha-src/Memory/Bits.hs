module Memory.Bits where

import Memory.Prelude
import Memory.Boolean
import Memory.Bitwise
-- import Memory.Digits

import Memory.Word (Bit)

-- TODO: Digitwise / digit shifting

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

-- TODO: Defaults from Digits, etc
class (Digits a Bit, Bitwise a) => Bits a where

    zeroBits :: a -- eg fillBits bottom
    oneBits :: a  -- eg fillBits top

    bit :: Int -> a
    setBit :: Int -> a -> a -- fillBit n, eq to setBit n top?
    clearBit :: Int -> a -> a -- eq to setBit n bottom?
    complementBit :: Int -> a -> a -- generalize to opBit? Infer from fmap?
    testBit :: Int -> a -> Bool

    bitCountMaybe :: a -> Maybe Int

-- TODO: Defaults from FiniteDigits, etc
class (FiniteDigits a Bit, Bits a) => FiniteBits a where

    bitCount :: a -> Int

    popCount :: a -> Int -- Hamming weight, countOnes
    countTrailingZeros :: a -> Int
    lowestSetBit :: a -> Maybe Int

-- TODO: Defaults from FixedDigits, etc
class (FixedDigits a Bit, FiniteBits a) => FixedBits a where

    bitWidth :: Proxy a -> Int
    countLeadingZeros :: a -> Int
    highestSetBit :: a -> Maybe Int



-- Ancillary classes relating to numeric interpretations
-- Needs more work

class (Bits a) => NumBits a where
    zero :: a
    one :: a
    isSigned :: Proxy a -> Bool
    fromIntegral :: (Integral i) => i -> a
    -- I would also like somewhere:
    -- fromFractional :: (Integral i, Integral j) => i -> j -> a -- where i.j

class (NumBits a) => IntBits a where
    toIntegral :: (Integral i) => a -> i

class (NumBits a) => SignedBits a where
    sign :: a -> a
    magnitude :: a -> a

-- NOTE: Natural will be Cardinal
class (NumBits a) => UnsignedBits a where
    toNatural :: a -> Natural
    fromNatural :: Natural -> a

class (SignedBits a) => TwosComplementBits a where
    signBitIndex :: a -> Int
    twosNegate :: a -> a
    -- TODO: Separate the concept of overflows / checking for them into its own class
    additionOverflows :: a -> a -> Bool
    subtractionOverflows :: a -> a -> Bool

class (SignedBits a) => OnesComplementBits a where
    onesNegate :: a -> a
    isNegativeZero :: a -> Bool

class (SignedBits a) => SignMagnitudeBits a where
    extractSign :: a -> Bool
    extractMagnitude :: a -> a
    fromSignMagnitude :: Bool -> a -> a
