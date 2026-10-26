module Memory.Word.Compound where

import Memory.Prelude

-- Important note: I really liked the feel of the original in sandbox/Word.hs
-- 'CompoundWord' lost some of that.

-- TODO: COMBINE THIS WITH DIGITS?

-- NOTE: This generalizes to memory cells of arbitrary nature; there is little
-- difference aside from nomenclature

-- TODO: Something like:
-- class Architecture arch where
--     type BaseLogicalUnit      arch :: Type
--     type BaseAddressableUnit  arch :: Type
--     type BaseAddressingScheme arch :: Type
-- type family BaseArchitecture word
-- Eg:
--      instance Architecture X86_64 where
--          type BaseLogicalUnit      X86_64 = Bit
--          type BaseAddressableUnit  X86_64 = Word8
--          type BaseAddressingScheme X86_64 = BigEndian
-- NOTE: An architecture is related to a set of types:
-- - Signed and unsigned char, int, size, address, ptrdiff, uintptr, intptr
-- - char / byte is smallest addressible unit (size 1) is at least 8 bits (C has CHAR_BIT, min 8)
-- - char should probably mean default character same way int means default integer
-- - short (aka short int) is 'small int'
-- - long (aka long int) is 'large int', int can be anywhere in between
-- - uint and int also have eg int_fastN_t or uint_least16_t variants but thats overkill
-- - Finally there's float, double, long double, bool, void, ptr (ptr is special)
-- Essentially, this what the LP64, ILP64 data models are for
-- - stands for Long, Pointer, 64-bit / Int, Long, Pointer, 64-bit
-- class DataModel arch where
--     type ByteSize arch
--     type ShortSize arch
--     type IntSize arch
--     type LongSize arch
--     type LongLongSize arch
--     type PointerSize arch
-- TODO: LP32, ILP32, LP64, LLP64, ILP64, SILP64
-- NOTE: The data model is about sizes, and doesn't include endian-ness / addressing scheme
-- NOTE: Doesn't deal with eg bit-addressable
-- Erlang has Bitstrings (a sequence of bits of any size eg 7-bits) and binaries (byte aligned bitstrings evenly divisible by 8 / made  of octets)

-- I thiiiink... Split into Digits, and Word (is / has a fixed word size)
-- So, Digits, DigitOrder

-- NOTE:
-- - Digital = discrete digit values (or cellular / cells)
-- - binary = bit-digital
-- - a word is fixed sized data made up of some digit type
-- there are other digits, like qubits, but also ternary decimal and BCD

-- Instead of digit, char? Or does digit generalize eg Word Word64 Byte AND Word Byte Bit
class CompoundWord word digit where
    proxyDynamicWordSize :: word -> Proxy digit -> Int

class (CompoundWord word digit) => FixedWord word digit where

    type FixedWordSize word digit
    proxyFixedWordSize :: Proxy word -> Proxy digit -> Int

-- NOTE: Before, we had type Endian word digit somewhere giving us a native
-- endianness. We need to replicate that somewhere
-- NOTE: The byte-order package / System.ByteOrder is endianness like memory
-- - See the Fixed :: ByteOrder -> Type -> Type GADT which is like As
-- - https://hackage.haskell.org/package/byte-order-0.1.3.1/docs/System-ByteOrder.html
class (CompoundWord word digit) => WordOrder endian word digit where

    -- NOTE: doesn't mention endian probably needs to be in its own class eg Word => WordOrder => WordAddress(able)
    type Endian word digit :: Type -- AddressingScheme
    type WordAddr endian word digit :: Type

    proxyWordAddr
        :: Proxy endian
        -> Proxy word
        -> Proxy digit
        -> Int
        -> WordAddr endian word digit

class (WordOrder endian word digit) => WordAccess endian word digit where

    proxyWordAccess
        :: Proxy endian
        -> Proxy word
        -> Proxy digit
        -> word -> WordAddr endian word digit -> digit
