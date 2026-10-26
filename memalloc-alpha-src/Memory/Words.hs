{-# LANGUAGE
    DataKinds
,   AllowAmbiguousTypes
#-}

-- A word is an architecture-defined machine word, a set of memory units
-- Importantly, they do not (yet) have an integer value ascribed to them
-- TODO: Integrate with:
-- - /Users/leo/git/apotheca/haskell-publish/mem/membase/src/Memory/U.hs
-- - U is WordN
-- - F is FloatN
-- It is also a better way of accomplishing what Endo(map) was trying to do:
-- - /Users/leo/git/apotheca/haskell-publish/mem/membase/src/Memory/Endo.hs
-- We can also consider 'Digital' as power-of-2 memory eg covering `Word w Bit`
-- - /Users/leo/git/apotheca/haskell-publish/mem/membase/src/Memory/Digital.hs
-- This new stuff mashes these concepts together nicely (esp with the boolean stuff)
-- Basically slamming it into this too:
-- - https://discourse.haskell.org/t/using-rgb-types-to-gain-intuition-about-type-level-programming-and-generics/13651
-- which is where Bitfield came from (also in membase)
module LHC.Words where

import Prelude hiding (Word)

import Data.Bits
import Data.Proxy
import Data.Word hiding (Word)
import Data.Int hiding (Int)
import GHC.TypeNats

-- NOTE: We just assume native arch is big-endian
-- NOTE: Bits users with little-endian (LSB-first) bit indexing

leByte :: (Integral i, Bits i) => Int -> Int -> i -> Word8
leByte _ 0 i = fromIntegral (i .&. 0xFF)
leByte _ n i = fromIntegral ((shiftR i (8 * n)) .&. 0xFF)

-- leBytes :: (Integral i, Bits i) => Int -> i -> [Word8] -> [Word8]
-- leBytes sz d rbs = foldr (\ n acc -> leByte sz n d : acc) rbs [ 0 .. (sz - 1) ]


-- NOTE: Size in *bytes*, not bits (maybe change?)
beByte :: (Integral i, Bits i) => Int -> Int -> i -> Word8
beByte sz n i = fromIntegral ((shiftR i (8 * ((sz - n) - 1))) .&. 0xFF)

-- beBytes :: (Integral i, Bits i) => Int -> i -> [Word8] -> [Word8]
-- beBytes sz d rbs = foldr (\ n acc -> beByte sz n d : acc) rbs [ 0 .. (sz - 1) ]


{-

-- foldBytes :: (Int -> Int -> i -> Word8) -> Int -> i -> [Word8] -> [Word8]

-- foldWords sz

-- NOTE: BINARY is anything with BITS, BITSTRINGS
-- So, Dyadic / Radix-2 / Power-of-two / "Dynary" / Words / Wordary / Architecture / Groupings / Chunkable / ByteString
-- NOTE: Fixed-width just means a know bit size, not necessarily dyadic

-- A class for endian-like things
-- TODO: Better name - bitmap, bytemap, endian, byteorder
class (FiniteBits a) => Bitmap a where
    byteAddr    :: a -> Int -> Int
    byteAt      ::
    bitaddr     :: a -> Int -> Int

class (FiniteBits a) => Bitmappable a where
    type Bitmap a

class Wordmap endian w bs where
    testWord :: Int -> bs -> w

foldBitmapBytes f sz d rbs = foldr (\ n acc -> f sz n d : acc) rbs [ 0 .. (sz - 1) ]

-- W


-- These two functions share almost identical code:

--  > leBytes :: (Integral i, Bits i) => Int -> i -> [Word8] -> [Word8]
--  > leBytes sz d rbs = foldr (\ n acc -> leByte sz n d : acc) rbs [ 0 .. (sz - 1) ]

--  > beBytes :: (Integral i, Bits i) => Int -> i -> [Word8] -> [Word8]
--  > beBytes sz d rbs = foldr (\ n acc -> beByte sz n d : acc) rbs [ 0 .. (sz - 1) ]

-- This generalizes to the following function:

--  > foldBytes f sz d rbs = foldr (\ n acc -> f sz n d : acc) rbs [ 0 .. (sz - 1) ]

-- But with FiniteBits, we can provide the size via (finiteBitSize $ undefined :: i) and even define a bitmap address that generalizes endianness:

--  > class (FiniteBits a) => Bitmap a where
--  >     byteaddr    :: a -> Int -> Int
--  >     bitaddr     :: a -> Int -> Int
--  >     byte

-- This generalizes the function further

-}

-- NOTE: Accidentally developed this fully here instead of moving it.
-- TODO: Move this to the appropriate place

-- TODO: foldWords (like foldBytes but generalized)
-- TODO: Classes / functions for converting between different word orders

-- TODO: Type families to automatically generate because we actually need to
-- start with eg raw bits:
--      Word Bit Bit
-- and then build up from there. It is a polynomial amount of instances, so the
-- type families are worth the added complexity



-- Size families

type family BitSize w :: Nat
type instance BitSize Bool   = 1
type instance BitSize Word8  = 8
type instance BitSize Word16 = 16
type instance BitSize Word32 = 32
type instance BitSize Word64 = 64
type instance BitSize Int8   = 8
type instance BitSize Int16  = 16
type instance BitSize Int32  = 32
type instance BitSize Int64  = 64

type family ByteSize w :: Nat
type instance ByteSize Bool   = 1
type instance ByteSize Word8  = 1
type instance ByteSize Word16 = 2
type instance ByteSize Word32 = 4
type instance ByteSize Word64 = 8
type instance ByteSize Int8   = 1
type instance ByteSize Int16  = 2
type instance ByteSize Int32  = 4
type instance ByteSize Int64  = 8



-- Word aka Bitmap/pable, maybe CompoundWord
-- TODO: Connect with Memory.Digital (basically, "has a base unit", eg Digital d ~ Word d (Digit d))
-- NOTE: Use of KnownNat / KnownWordSize makes this FiniteWord or like
-- memory:Data.ByteArray.Sized, but tis fine
-- NOTE: Word size MIGHT depend on endianness, eg, imagine a ECCBigEndian
-- with "only" 6 byte available out of 8 using the others as parity bytes.
-- In this case, Word Size should take an endian argument as well, but that is
-- a huge amount of overkill for now - the fact that we support arbitrary
-- bitmaps such as middle endian is already one abstraction layer.
-- type KnownWordSize cw sw = KnownNat (WordSize cw sw)
class (KnownNat (WordSize cw sw)) => Word cw sw where

    type WordSize cw sw :: Nat

    proxyWordSize :: Proxy cw -> Proxy sw -> Int
    proxyWordSize _ _ = fromIntegral (natVal (Proxy @(WordSize cw sw)))

-- NOTE: Requires AllowAmbiguousTypes
wordSize :: forall cw sw . Word cw sw => Int
wordSize = proxyWordSize (Proxy @cw) (Proxy @sw)

-- Word order aka Endian-ness


-- Aka Bitmappable or Wordmap or something
-- Eg, BigEndian Word16 Word8
-- Compound word, sub wod
class (Word cw sw) => WordOrder endian cw sw where
    -- Aka Bitmap
    type Endian cw sw :: *
    type Endian cw sw = BigEndian
    
    proxyWordAddr :: Proxy endian -> Proxy cw -> Proxy sw -> Int -> Int

-- TODO: Rename wordAddrEndian, make new wordAddr to match wordEndian and word
wordAddrEndian :: forall endian cw sw . WordOrder endian cw sw => Int -> Int
wordAddrEndian = proxyWordAddr (Proxy @endian) (Proxy @cw) (Proxy @sw)

wordAddr :: forall cw sw . WordOrder (Endian cw sw) cw sw => Int -> Int
wordAddr = wordAddrEndian @(Endian cw sw) @cw @sw
-- Why does this need @cw @sw but 'word' doesn't? 
-- wordAddr = proxyWordAddr (Proxy @(Endian cw sw)) (Proxy @cw) (Proxy @sw)

newtype As endian w = MkAs w

-- Word access aka Bitmappable, maybe WordAddressible?

class (WordOrder endian cw sw) => WordAccess endian cw sw where
    proxyWord :: Proxy endian -> Proxy cw -> Proxy sw -> cw -> Int -> sw

wordEndian :: forall endian cw sw . WordAccess endian cw sw => cw -> Int -> sw
wordEndian = proxyWord (Proxy @endian) (Proxy @cw) (Proxy @sw)

-- NOTE: Currently requires:
--      word @Word64 @Word8 n ix
-- need to rearrange the forall to allow for:
--      word @Word8 (n :: Word64) 0
word :: forall cw sw . (WordAccess (Endian cw sw) cw sw) => cw -> Int -> sw
word = wordEndian @(Endian cw sw)

--



-- Big Endian

data BigEndian

type family BE w

type instance BE Word8  = Word8
type instance BE Word16 = Word16
type instance BE Word32 = Word32
type instance BE Word64 = Word64
type instance BE Int8   = Int8
type instance BE Int16  = Int16
type instance BE Int32  = Int32
type instance BE Int64  = Int64

-- Little Endian

data LittleEndian
type family LE w

type instance LE Word8  = Word8
type instance LE Word16 = As LittleEndian Word16
type instance LE Word32 = As LittleEndian Word32
type instance LE Word64 = As LittleEndian Word64
type instance LE Int8   = Int8
type instance LE Int16  = As LittleEndian Int16
type instance LE Int32  = As LittleEndian Int32
type instance LE Int64  = As LittleEndian Int64

-- Folding

{- Eg
ghci> foldrWordsEndian @BigEndian @Word64 @Word8 (:) [] 0x0123456789ABCDEF
[1,35,69,103,137,171,205,239]
ghci> foldrWordsEndian @LittleEndian @Word64 @Word8 (:) [] 0x0123456789ABCDEF
[239,205,171,137,103,69,35,1]
-}
foldrWordsEndian
    :: forall endian cw sw a . (WordAccess endian cw sw)
    => (sw -> a -> a) -> a -> cw -> a
foldrWordsEndian f z cw = foldr (\ i acc -> f (wordEndian @endian cw i) acc) z [0 .. wordSize @cw @sw - 1]

toWordsEndian :: forall endian cw sw . (WordAccess endian cw sw) => cw -> [sw]
toWordsEndian = foldrWordsEndian @endian @cw @sw (:) []

foldrWords :: forall cw sw a . (WordAccess (Endian cw sw) cw sw)
    => (sw -> a -> a) -> a -> cw -> a
foldrWords = foldrWordsEndian @(Endian cw sw) @cw @sw @a

toWords :: forall cw sw . (WordAccess (Endian cw sw) cw sw) => cw -> [sw]
toWords = foldrWords (:) []

-- fromWords :: forall cw sw . (WordAccess (Endian cw sw) cw sw) => [cw] -> cw
-- fromWords = foldr

-- FINALLY we can tie endian-ness together with shifting words
-- Need to deal with lifting a boolean subword to its compound word
-- Need to integrate with allocation

-- Instances

-- TODO: Specialize these like
-- instance WordAccess BigEndian Word64 Word8 where
--     proxyWord pe pcw psw cw swi = sw where
--         addr = proxyWordAddr pe pcw psw swi
--         sw = specializedGetWord8 addr cw  xxz
-- where
--     specializedGetWord8 :: (Integral i, Bits i) => Int -> i -> Word8
--     specializedGetWord8 addr i = fromIntegral ((shiftR i (8 * addr)) .&. 0xFF)
-- for cpu-atomic types and pointer-plucking for large arrays
byteAt :: (Integral i, Bits i) => Int -> i -> Word8
byteAt addr i = fromIntegral ((shiftR i (8 * addr)) .&. 0xFF)

-- Word8

instance Word Word8 Word8 where
    type WordSize Word8 Word8 = 1

instance WordOrder BigEndian Word8 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Word8 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Word8 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Word8 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Word16

instance Word Word16 Word8 where
    type WordSize Word16 Word8 = 2

instance WordOrder BigEndian Word16 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Word16 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Word16 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Word16 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Word32

instance Word Word32 Word8 where
    type WordSize Word32 Word8 = 4

instance WordOrder BigEndian Word32 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Word32 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Word32 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Word32 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Word64

instance Word Word64 Word8 where
    type WordSize Word64 Word8 = 8

instance WordOrder BigEndian Word64 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Word64 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Word64 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Word64 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Int8
instance Word Int8 Word8 where
    type WordSize Int8 Word8 = 1

instance WordOrder BigEndian Int8 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Int8 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Int8 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Int8 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Int16
instance Word Int16 Word8 where
    type WordSize Int16 Word8 = 2

instance WordOrder BigEndian Int16 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Int16 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Int16 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Int16 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Int32
instance Word Int32 Word8 where
    type WordSize Int32 Word8 = 4

instance WordOrder BigEndian Int32 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Int32 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Int32 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Int32 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw

-- Int64
instance Word Int64 Word8 where
    type WordSize Int64 Word8 = 8

instance WordOrder BigEndian Int64 Word8 where
    proxyWordAddr _ _ _ idx = idx

instance WordAccess BigEndian Int64 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = beByte sz swi cw

instance WordOrder LittleEndian Int64 Word8 where
    proxyWordAddr _ pcw psw idx = addr where
        sz = proxyWordSize pcw psw
        addr = (sz - 1) - idx

instance WordAccess LittleEndian Int64 Word8 where
    proxyWord _ pcw psw cw swi = sw where
        sz = proxyWordSize pcw psw
        sw = leByte sz swi cw


{-
w = 0x0123456789ABCDEF :: Word64
word @Word64 @Word8 w 0
> 1
word @Word64 @Word8 w 7
> 239
wordEndian @LittleEndian @Word64 @Word8 w 0
> 239
wordEndian @LittleEndian @Word64 @Word8 w 7
> 1
-}