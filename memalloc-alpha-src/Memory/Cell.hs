module Memory.Cell where

import Memory.Prelude
import Memory.Memory

-- This is a superclass for memory organized into discrete units
-- This is different from the units being discrete (quantized themselves)
-- Cells may be arbitrary data - classical, analog, quantum, cons-cells
-- NOTE: Is the base storage unit, not the base logical unit (eg, Byte cells with Bit units)
class Cellular mem where
    type family Cell mem :: Type

class Digital mem where

class Binary mem where -- Digital with Bit cells


{-
Cellular
    Digital (all cells are the same)
        Binary

    

-}