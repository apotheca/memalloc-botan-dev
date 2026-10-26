module Memory.Memo.Retainable where

import Memory.Prelude
import Memory.Memo

class (Memory ref) => Retainable ref where
    
    retainCount :: ref a -> Int
    retain :: ref a -> IO ()
    release :: ref a -> IO ()
    autoreleasing :: ref a -> (ref a -> IO a) -> IO a
    -- TODO: Needs bracketing
    autoreleasing ref f = do
        retain ref
        a <- f ref
        release ref
        pure a

    -- NOTE: Only exposed for implementation purposes.
    unsafeSetRetainCount :: ref a -> Int -> IO ()
    unsafeRelease :: ref a -> IO ()

-- TODO: Classes for weak pointers

-- This corresponds to System.Mem.Weak, needs fleshing out
class Weakable ref where
    type family Weak ref
