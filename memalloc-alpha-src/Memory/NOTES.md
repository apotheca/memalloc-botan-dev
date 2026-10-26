Its the data model

That defines eg

type Int = Two’s complement big-endian word 32

And then

type family Cell mem

type Binary = (Cell mem ~ Bit)

?

-- Cellular is to Digital is to Worded
-- Cell is a / the single base addressable unit
-- Digital is polymorphic and allows for composite cells
-- Word is allows for different addressing schemes
-- - Including addressing of the smallest logical unit which may be sub-cell
-- We could cast digit as 'sub-cell' and word as 'compound cell'
-- I feel like Digit is smallest logical unit - digits compose cells, cells may compose words
-- I'm trying to leave this open to tying to mathematical discretization in the math library, but that's super-overkill and a blocker to actually getting this out. So this is fine for now

class Digital ds d where

-- Or DigitAddress
class (Digital ds d) => DigitOrder ds d where
    type DigitAddr ds d

class (Digital w d) => Word w d where
    type WordSize w d

-- Or WordAddress
class (Word w d) => WordOrder e w d where
    type WordAddr e w d

class (WordOrder e w d) => WordAccess e w d where



-- NOTE: Need a Class Eq > Partial Order / Address > Order / Ix
-- Then Addr is the host address, which we can tie to:
-- Pointer > AddrPointer > UIntPointer / IntPointer
-- We also then need a Size that can always successfully turn into a Addr

-- It would be good to reflect this sort of 'promotion' (and potentially-lossy demotion) which would work well with the storage size classes

-- Host should be a generic data model (C's data model includes short and long
type HostBool = Prelude.Bool
type HostUInt = Prelude.Word
type HostInt = Prelude.Int
type HostFloat = PreludeDouble
type HostSize
type HostAddr
type HostPtr


----

Maybe keep endianness as a single data type:

data Endian
    = BigEndian
    | LittleEndian
    | NativeEndian
    | PDPEndian -- Middle-endian
    | CustomEndian (forall a . (IsEndian a) => a)

-- Formerly KnownEndianness
class KnownEndian (e :: Endian) where
    endian :: Endian

--

NOTE: Need to pull in the KnownU stuff too (KnownWord is better)

NOTE: Probably should just be okay with WordN (n :: Nat) being the instance of Word (WordN n) Bit

--

Do need to at least get some of the better 'bits' subclasses relating to numberness


--

NOTE:

memory's Endian and ByteSwap:

data Endianness
    = LittleEndian
    | BigEndian

getSystemEndianness :: Endianness

newtype BE a = MkBE { unBE :: a }

newtype LE a = MkLE { unLE :: a }

fromBE :: ByteSwap a => BE a -> a
toBE :: ByteSwap a => a -> BE a
fromLE :: ByteSwap a => LE a -> a
toLE :: ByteSwap a => a -> LE a

class Storable a => ByteSwap a where
    byteSwap :: a -> a

We do need this functionality

--

NOTE: Need to better separate value logic (eg what a unit represents) from structural topology (how units are grouped and addressed)

Need to separate base logical unit from base addressable unit

Value logic type / Base logical units, eg what is the data made of and what algebras / functions can it express?

	⁃	bit
	⁃	qubit
	⁃	float
	⁃	simdarray
	⁃	signal

Topology / Base addressable units

	⁃	Cell - base addressable unit
	⁃	Digit - base logical / subcell unit, often is the value logic type?)

Needs more work

Base logical unit (or Digit) is the smallest fundamental piece of information handled by the system's logic type.

	⁃	Classical BIt
	⁃	Quantum Qubit
	⁃	Analog Signal
	⁃	DIgitizedAnalog Float
	⁃	SIMD FloatNxM
	⁃	Cons-cell or atom

Base Addressable unit (aka Cell) is the smallest chunk of memory that has a unique address

	⁃	Bit
	⁃	Byte
	⁃	Pointer
	⁃	Register
	⁃	Quantum register

Hmmm need to separate Bool from Bit and things. Lets try some classes

-- The value / logic layer

class Logic logic where
    type LogicalUnit logic :: Type

data Classical
instance Logic Classical where
    type LogicalUnit Classical = Bool -- Or Bit?

data Quantum
instance Logic Quantum where
    type LogicalUnit Quantum = Qubit

data Analog
instance Logic Analog where
    type LogicalUnit Analog = Signal -- Or float

-- The granularity / addressability layer

-- NOTE: Doesnt link the logic type, radix is number of possible states and not all logic or memory types support that (eg analog signals with infinite states)
-- The lack of  mention of logic in digit or radix means this isnt right
class (Logic logic) => DigitalMemory mem logic where
    type Digit mem :: Type
    radix :: Proxy mem -> Int

class AddressableMemory mem where
    type Addr mem :: Type
    type Cell mem :: Type
    readCell :: mem -> Addr mem -> IO (Cell mem)
    writeCell :: mem -> Addr mem -> Cell mem -> IO ()

class (DigitalMemory mem log, AddressableMemory mem) => CompositeCellMemory mem log where
    digitsPerCell :: Proxy mem -> Int
    unpackCell :: Cell mem -> [Digit mem]
    packCell :: [Digit mem] -> Cell mem
--

Need BitList = [BIt], ByteList = [Byte], BitArray, ByteArray = ByteString classes - where BitL

--

Host vs Native vs System nomenclature, should prefer either Host or System (I think I like Host)

--

Need the proxy functions in typeclasses to have convenient non-proxy functions designed for easy type application


--

Need to expand on 'temporary memory views' as a concept (eg slicing)

--

Memory concepts checklist

- ownership and borrow checking like rust - zero runtime but requires compile-time analysis
- reference counting like swift
- tracing / stop-the-world GC (good for games and things with predictable pauses / timing)
 - regions / arenas with escape analysis
 - bounds-checking and tagged pointers
 - arena allocators are for short-lived bulk allocation eg scope allocator { ... } - pros: bump-allocate and bulk free everything in o(1) time, cons: requires a (deep) copy to move things out and you need to forbid out-of-scope access to avoid use-after-free
 - temporary / transient memory views and slicing - pros: allows zero-cost "copying" of immutable data, cons: requires copy-on-write, potentially requires ref-counting the buffer if views take ownership
 - Cross-thread long-lived state such as threadable (thread-local isolated storage) and concurrent (lockable / mutexed / atomically accessable cross-thread actors)
 - mmap for huge data structures that can't fit into memory all at once
- ffi boundaries and a cbuffer that holds the ptr, size, and a free callback (thats what foreignptr is)



---


NOTE: Addressable is the smallest unit of data that can be operated on at once

This means that even though the bits of a byte can be extracted with masking and
shifting, the bytes are not *immediately* or *individually* addressable.