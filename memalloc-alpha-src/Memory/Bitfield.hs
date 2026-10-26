{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

-- TODO: Needs better integration
-- TODO: Rename Field to Bitfield
-- TODO: Rename Bitfield to Bitfields
module Memory.Bitfield where

import Memory.Prelude
import Memory.Word

import Data.Bits

-- TODO: Probably use datakinds instead of symbols?
-- Then can generate a list of fields from the field sum-type constructors
newtype Field (name :: Symbol) (width :: Nat) = Field (U width)

-- Maybe can newtype Bitfield = fs?
data Bitfield (fs :: [Type]) where
    Nil  :: Bitfield '[]
    Cons :: Field name width -> Bitfield fs -> Bitfield (Field name width : fs)

class (KnownU (PackedWidth fs)) => Packable (fs :: [Type]) where
    type PackedWidth fs :: Nat
    packFields :: Bitfield fs -> U (PackedWidth fs)

instance Packable '[] where
    type PackedWidth '[] = 0 -- TODO: Rename PackedWidth?
    packFields Nil = 0

instance
    (    KnownU width, KnownU (width + PackedWidth fs), Packable fs
    ) => Packable (Field name width : fs) where
    type PackedWidth (Field name width : fs) = width + PackedWidth fs
    
    packFields (Cons (Field val) rest) = 
        let offset  = fromIntegral $ natVal (Proxy @(PackedWidth fs))
            bits    = fromIntegral val `shiftL` offset
        in  bits .|. fromIntegral (packFields rest)

newtype Packed (fs :: [Type]) = Packed { getPacked :: U (PackedWidth fs) }

deriving newtype instance Eq   (U (PackedWidth fs)) => Eq   (Packed fs)
deriving newtype instance Ord  (U (PackedWidth fs)) => Ord  (Packed fs)
deriving newtype instance Num  (U (PackedWidth fs)) => Num  (Packed fs)
deriving newtype instance Show (U (PackedWidth fs)) => Show (Packed fs)
deriving newtype instance Enum (U (PackedWidth fs)) => Enum (Packed fs)
deriving newtype instance Bounded (U (PackedWidth fs)) => Bounded (Packed fs)
deriving newtype instance Bits (U (PackedWidth fs)) => Bits (Packed fs)
deriving newtype instance FiniteBits (U (PackedWidth fs)) => FiniteBits (Packed fs)
deriving newtype instance Real (U (PackedWidth fs)) => Real (Packed fs)
deriving newtype instance Integral (U (PackedWidth fs)) => Integral (Packed fs)

pack :: (Packable fs) => Bitfield fs -> Packed fs
pack fs = Packed $ packFields fs

type family FieldOffset (name :: Symbol) (fs :: [Type]) :: Nat where
    FieldOffset name (Field name w : fs) = PackedWidth fs
    FieldOffset name (Field other w : fs) = FieldOffset name fs
    FieldOffset name '[] = TypeError (
        'Text "FieldOffset: Field not found: "
        ':<>: 'ShowType name
        ) -- Or '0'

fieldWidth :: forall name fs. (KnownU (FieldWidth name fs)) => Int
fieldWidth = fromIntegral $ natVal (Proxy @(FieldWidth name fs))

type family FieldWidth (name :: Symbol) (fs :: [Type]) :: Nat where
    FieldWidth name (Field name w : fs) = w
    FieldWidth name (Field other w : fs) = FieldWidth name fs
    FieldWidth name '[] = TypeError (
        'Text "FieldWidth: Field not found: "
        ':<>: 'ShowType name
        ) -- Or '0'

fieldOffset :: forall name fs. (KnownU (FieldOffset name fs)) => Int
fieldOffset = fromIntegral $ natVal (Proxy @(FieldOffset name fs))

-- TODO: Probably rename to Peekable, peek?
class
    (    KnownU (FieldOffset name fs), KnownU (FieldWidth name fs), Packable fs
    ) => Pluckable (name :: Symbol) (fs :: [Type]) where
    pluck :: Packed fs -> U (FieldWidth name fs)

instance
    (    KnownU (FieldWidth name fs), KnownU (FieldOffset name fs), Packable fs
    ) => Pluckable name fs where
    -- TODO: Can we move the KnownU constraints to the default impl sig?
    pluck (Packed val) =
        let offset = fieldOffset @name @fs
            width  = fieldWidth @name @fs
            mask   = (1 `shiftL` width) - 1
            bits = val `shiftR` offset
        in fromIntegral (mask .&. bits)

class
    (    KnownU (FieldOffset name fs), KnownU (FieldWidth name fs), Packable fs
    ) => Pokeable (name :: Symbol) (fs :: [Type]) where
    poke :: U (FieldWidth name fs) -> Packed fs -> Packed fs

instance
    (    KnownU (FieldOffset name fs), KnownU (FieldWidth name fs), Packable fs
    ) => Pokeable name fs where
    poke field (Packed bits) =
        let offset = fieldOffset @name @fs
            width  = fieldWidth @name @fs
            mask   = ((1 `shiftL` width) - 1) `shiftL` offset -- Cacheable, eg via FieldMask or something
            val    = fromIntegral field `shiftL` offset
        in Packed $ (bits .&. complement mask) .|. val

-- Usage Example: R5G6B5

type R5G6B5 = '[Field "Red" 5, Field "Green" 6, Field "Blue" 5]

packR5G6B5 :: U 5 -> U 6 -> U 5 -> Packed R5G6B5
packR5G6B5 r g b = pack
    $ Cons (Field @"Red" r)
    $ Cons (Field @"Green" g)
    $ Cons (Field @"Blue" b)
    $ Nil

pluckGreen :: Packed R5G6B5 -> U 6
pluckGreen = pluck @"Green"

pokeGreen :: U 6 -> Packed R5G6B5 -> Packed R5G6B5
pokeGreen = poke @"Green"

-- TODO: A HasField class or type function?
--
-- class (KnownU (FieldWidth name fs), KnownU (FieldOffset name fs)) => HasField (name :: Symbol) (fs :: [Type]) where
--
--     proxyFieldWidth :: Proxy (FieldWidth name fs) -> Int
--     proxyFieldWidth proxy = fromIntegral $ natVal proxy
--
--     proxyFieldOffset :: Proxy (FieldOffset name fs) -> Int
--     proxyFieldOffset proxy = fromIntegral $ natVal proxy
--
-- type family FieldInfo (name :: Symbol) (fs :: [Type]) :: Bool where
--     FieldInfo name (Field name w : fs) = w
--     FieldInfo name (Field other w : fs) = FieldInfo name fs
--     FieldInfo name '[] = TypeError (
--         'Text "FieldInfo: Field not found: "
--         ':<>: 'ShowType name
--         )
