module Memory.Bitwise where

import Memory.Prelude
import Memory.Boolean

-- class Digitwise ds d where

--     shiftDigits

-- TODO: Give these back their longer name; these are better as opcode names
-- TODO: Split this up into LogicalShift, ArithmeticShift, CircularShift, Digits a Bit => Bitshift a
class (Boolean a) => Bitwise a where

    -- TODO: Don't forget shift-extend later

    shift :: a -> Int -> a
    ashift :: a -> Int -> a
    rotate :: a -> Int -> a

    -- Logical shifts
    shl :: a -> Int -> a
    shr :: a -> Int -> a

    -- Arithmetic shifts - maaaaybe place in a separate class?
    -- It does imply a particular numeric interpretation of the bits
    sal :: a -> Int -> a
    sar :: a -> Int -> a

    -- Circular shifts
    rol :: a -> Int -> a
    ror :: a -> Int -> a

    sal = shl
