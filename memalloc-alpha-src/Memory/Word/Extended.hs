module Memory.Word.Extended where

-- TODO: Classes and types for compound / extended word sizes
-- Word pairs and tuples for efficient representation
-- The CompositeWord here is a better reflection of Word words word, so then
-- Word can stay meaning Word word digits, a fixed-sized Digital

{-
THESE NEED INTEGRATION
-}

-- data Word128 = MkWord128 !Word64 !Word64

-- -- TODO: Common word sizes
-- -- Eg, Word80, 96, 128, 160, 192, 256, 384, 512, 768, 1024

-- data Word256 = MkWord256 !Word128 !Word128
-- data Word512 = ...

-- class WordPair wp w where
--     upperWord :: wp -> w
--     lowerWord :: wp -> w
--     fromUpperLower :: w -> w -> wp
-- instance WordPair Word128 Word64 where
--     ...

-- -- Should we extend to an arbitrary number of words?
-- -- No - this is covered by eg `Memory addr word / WordArray`
-- class ExtendedWord ws w where
--     words :: [w]

-- -- What about a fixed but non-pair number of words?
-- -- This allows for composite words made up of eg 3, 4 subwords which allows for
-- -- eg Word384 or Word768
-- -- Yes, this also describes SIMD:
-- -- - Byte = Smallest addressable unit
-- -- - Word = Largest addressable unit
-- -- - SIMD = Composite word, not a 'unit' per se, but a SIMDBlock would be a 'word'
-- class CompositeWord ws w where
--     words :: ws ->[w]
--     fromWords :: [w] -> ws
--     wordCount :: Proxy ws -> Int
--     -- Or equivalently?
--     type WordTuple ws :: * -> *
--     fromWordTuple :: WordTuple ws -> ws w
--     toWordTuple :: ws -> WordTuple ws w
-- data Word384 = MkWord384 !Word128 !Word128 !Word128
-- instance CompositeWord Word384 Word128
--     words
--     type WordTuple Word384 = (!Word128, !Word128, !Word128)
--     fromWordTuple (a, b, c) = MkWord384 a b c
--     toWordTuple (MkWord384 a b c) = (a, b, c)
--     wordCount Proxy = 3
