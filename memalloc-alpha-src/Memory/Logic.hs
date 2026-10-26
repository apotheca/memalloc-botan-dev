module Memory.Logic where

import Memory.Prelude

import Memory.Lattice

-- Oh look its the same five functions, again

class (Eq a) => Connective a where

    conjunction :: a -> a -> a
    default conjunction :: (MeetSemilattice a) => a -> a -> a
    conjunction = meet

    disjunction :: a -> a -> a
    default disjunction :: (JoinSemilattice a) => a -> a -> a
    disjunction = join

-- Positive logic
class (Connective a) => Positive a where

    -- false
    contradiction :: a
    default contradiction :: (LowerBoundedLattice a) => a
    contradiction = bottom

    tautology :: a
    default tautology :: (UpperBoundedLattice a) => a
    tautology = top

-- class PositiveLogical a where
class (Positive a) => Logical a where

    negation :: a -> a
    default negation :: (ComplementedLattice a) => a -> a
    negation = complement

class Logical a => Propositional a where

    refuted :: a -> Bool
    refuted = (== contradiction)

    affirmed :: a -> Bool
    affirmed = (== tautology)

    -- TODO: Probably add, is required for eg Kleene or Lukasiewicz algebras
    -- but can reasonably default to two-valued implication
    -- implication :: a -> a -> a
    -- implication a b = negation a `disjunction` b

    -- Ditto
    -- biconditional :: a -> a -> a

    -- Modus ponens?
    -- isValidInference :: Logic a => a -> a -> Bool
    -- isValidInference premise conclusion = 
    --     true (premise `implies` conclusion)

-- TODO: LogicUnit vs BaseLogicUnit?
class Logic a where
    type LogicUnit a :: Type

{-
Boolean logic (boolean lattice)
Bool base logical unit is the exemplar of the logic
Bit base information storage unit can represent the base logical 
Byte base addressable storage unit (or in rare cases, bit)
-- NOTE: most modern cpus are byte-addressable and can only emulate bit-addressable
-- NOTE: N bits gives you 2 ^ n mutually exclusive states (it is a sum type)
-}
data Classical-- Bool Bit storage

data Bool

data Bit

data Byte

-- NOTE: Can make classical polymorphic over its addressable unit
-- eg (Classical Byte) for byte-addressible architectures
-- POSTNOTE: Or see the Paradigm class
instance Logic Classical where
    type LogicUnit Classical = Bool -- The boolean algebra

{-
Closed 2d hilbert space logic (orthomodular lattice)
Hilb base logical unit (closed subspace)
Qubit base storage unit
Qureg base addressable unit (scalar unit)
-- NOTE: N qubits gives you 2 ^ n mutually co-existing states (it is a (tensor) product type)
-- NOTE: A collapsed qubit fits into a single complex number;
-- an uncollapsed qubit needs two complex numbers to simulate its superposition but a real qubit still only requires one
-- Qubits require operating over the entire 2^n history of the qubit simultaneously
-- Real quantum registers remain uncollapsed, but still fit in a single 'value'
-}
data Quantum

data Hilbertian

data Hilb -- Its like Bool to the Boolean, except for hilbert spaces

data Qubit = Qubit (Complex Double) (Complex Double)

type Qureg = [Qubit] -- An entangled set of qubits


-- Memory or computing paradigm.
-- Eg, Classical, Quantum, Analog, etc
class Paradigm p where

    -- Eg, Boolean, Hilbert, RealTimeSignalAnalysis / DSP
    type LogicalFramework p :: *

    -- Eg, Bool, Hilb, Differential / Signal
    type LogicalUnit p :: * -- NOTE: Aka, the functional unit / LU
  
    -- Might be able to split between logical and memory paradigms here
    -- Then we can have Classical = Logic Boolean, LU Bool; Binary  
    -- This better expresses DSP where base storage unit is bits, addr is words, but logic is floats / analog 

    -- Eg, Bit, Qubit, Packet / Amplitude
    type StorageUnit p :: * -- NOTE: AKA, information (storage) unit / ISU
  
    -- Eg, Byte, Quregister, Circuit
    type AddressableUnit p :: * -- NOTE: AKA, the placement unit / AU

-- Then:

type Binary p = (Paradigm p, LogicalFramework p ~ Boolean, LogicalUnit p ~ Bool, StorageUnit p ~ Bit)
type BitAddressable p = (Binary p, AddressableUnit p ~ Bit)
type ByteAddressable p = (Binary p, AddressableUnit p ~ Byte)

-- NOTE: If we break Paradigm up into LogicalFramework, MemoryFramework, they
-- combine into a computational framework / paradigm which gets paired with an
-- architecture to produce a machine, and a data model on top of that exposes
-- the base primitives for a language


class DataModel arch where
    -- Atom types
    type CardinalType arch :: Type
    type IntegerType arch :: Type
    type RationalType arch :: Type
    -- Reference / meta types
    type PointerType arch :: Type
    type Size arch :: Type
    type Address arch :: Type

{-
type HostBool  = Prelude.Bool
type HostUInt  = Prelude.Word
type HostInt   = Prelude.Int
type HostFloat = Prelude.Double
type HostSize  = ...
type HostAddr  = ...
type HostPtr   = ...
-}

class DataModel arch where
    type SmallestInteger arch :: Type   -- NOTE: Smallest ADDRESSABLE integer
    type SmallInteger arch :: Type
    type StandardInteger arch :: Type
    type LargeInteger arch :: Type
    type LargestInteger arch :: Type    -- NOTE: Largest ADDRESSABLE integer

-- TODO: LP32, ILP32, LP64, LLP64, ILP64, SILP64
class CDataModel arch where
    type CharSize arch :: Nat -- NOTE: C char = byte, because a word is made of characters instead of digits for some reason
    type ShortSize arch :: Nat
    type IntSize arch :: Nat
    type LongSize arch :: Nat
    type LongLongSize arch :: Nat
    type PointerSize arch :: Nat
    type SizeSize arch :: Nat
    type AddressSize arch :: Nat


-- NOTE: Classical still needs to Von Neumann vs Harvard architecture, but this
-- is actually the difference between Ptr / FunPtr and the reason for code vs
-- data segments in the program executable (and why things need marking as
-- executable - we live in a quasi-both world - unified address space, mixes code and data placementwise but not logically)