module Memory.Memo.Handle where

import Memory.Prelude
import Memory.Memo

-- NOTE: Somewhere in another attempt at this, is another handle class with a
-- very important note about equality, and indirect pointers.

class (Memory hdl) => Handle hdl where
    hdlEq :: hdl a -> hdl a -> Bool
    hdlHash :: hdl a -> Int
