module Memory.Bitmask where

import Memory.Prelude

import Data.Bits

-- NOTE: Safely ignores flag values < 0, assumes zero flag is 0, you can
-- override this if you wish
class (Eq a, Enum a, Bounded a, Bits (Bitmask a)) => Bitflags a where

    -- | The underlying bitmask's storage type eg Word8 etc
    type Bitmask a :: Type

    -- | The default storage type is Word64
    type Bitmask a = Word64

    -- zeroMask :: Bitmask a
    -- zeroMask = zeroBits

    zeroFlag :: a
    zeroFlag = toEnum 0

    maxFlag :: a
    maxFlag = maxBound

    -- allBits :: Bitmask a
    -- allBits = bitmask [zeroFlag..maxFlag]

    bitmask :: [a] -> Bitmask a
    bitmask flags = maskFlags flags zeroBits

    -- NOTE: Although the default implementation maps each flag to a single bit,
    -- this is not required, and you can override this if you wish
    flagBits :: a -> Bitmask a
    flagBits flag = case fromEnum flag of
        0 -> zeroBits -- error "unsafeFlagBit: empty flag has no bit"
        n -> bit (n - 1)

    -- TODO: flagValue that masks and right-shifts flagBits to get a numeric
    -- value - useful for multi-bit flags eg that are subfields
    -- Eg, data R5B6G5 = R | G | B where popCount (flagBits R) = 5, and so on

    maskFlag :: a -> Bitmask a -> Bitmask a
    maskFlag flag mask = mask .|. flagBits flag
    
    -- TODO: Maybe foldr
    maskFlags :: [a] -> Bitmask a -> Bitmask a
    maskFlags flags mask = foldl' (\ acc flag -> maskFlag flag acc) mask flags

    -- NOTE: Naively, zeroFlag has no bit, and so could always return True;
    -- however, it seem both sensible and useful to define it as matching the
    -- case of 'no bits set'; you can override this if you wish
    hasFlag :: Bitmask a -> a -> Bool
    hasFlag mask flag
        | flag == zeroFlag = mask == zeroBits
        | otherwise = let bs = flagBits flag in (mask .&. bs) == bs


lowestFlagBit :: (Bitflags a, FiniteBits (Bitmask a)) => a -> Int
lowestFlagBit = countTrailingZeros . flagBits

flagValue :: (Bitflags a, FiniteBits (Bitmask a), Integral (Bitmask a)) => Bitmask a -> a -> Int
flagValue mask flag = fromIntegral $ shiftR (mask .&. flagBits flag) (lowestFlagBit flag)

data Greek
    = None
    | Alpha
    | Beta
    | Gamma
    | Delta
    deriving stock (Eq, Ord, Enum, Bounded)

instance Bitflags Greek where

    type Bitmask Greek = Word8
