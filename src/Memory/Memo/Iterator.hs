module Memory.Memo.Iterator where

import Memory.Prelude
import Memory.Memo

class (Memory mem) => Iterator itr where
    next :: itr a -> IO (Maybe a)
    count :: itr a -> Int -- Or position

class Iterator itr => FiniteIterator itr where
    remaining :: itr a -> Int
    remaining = total - count
    total :: itr a -> Int
    total = count + remaining
    {-# MINIMAL remaining | total #-}

class Iterator itr => RestartableIterator itr where
    restart :: itr a -> itr a

-- NOTE: This is very close to a Stream class - eg, what LazyByteString is.
-- The design of a lazy or streaming memory type is that there is some way of
-- getting a pointer to the next segment of the stream, or maybe of specifying
-- a buffer of a given size that gets *filled* by the next segment(s).