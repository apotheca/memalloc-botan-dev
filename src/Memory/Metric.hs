{-# LANGUAGE
    AllowAmbiguousTypes
,   UndecidableInstances
#-}

module Memory.Metric where

import Memory.Prelude

-- This works but probably should do this at the value level
-- data MemorySize ... = MkMemorySize n metrix (Proxy unit)

data MemorySize (n :: Nat) metric unit

-- TODO: Return a memory size value that we can TURN INTO an integer
class KnownMemorySize (msz :: k) where
    proxyMemorySize :: Proxy msz -> Integer

class MemoryMetric prefix where
    -- proxyMemoryMetricMultiplier :: Proxy prefix -> Integer
    memoryMetricMultiplier :: prefix -> Integer

class KnownMemoryMetric (p :: k) where
    proxyMemoryMetric :: Proxy p -> k

instance
    ( KnownNat n
    , KnownMemoryMetric p
    , MemoryMetric std
    , p ~ (pfx :: std) -- Argh type magic
    ) => KnownMemorySize (MemorySize n p u) where
    proxyMemorySize _ = msz where
        n   = natVal (Proxy @n)
        pfx = memoryMetricMultiplier (proxyMemoryMetric (Proxy @p))
        msz = n * pfx

knownMemorySize :: forall s. KnownMemorySize s => Integer
knownMemorySize = proxyMemorySize (Proxy @s)

-- Convenience function taking all 3 arguments separately
memorySize :: forall n metric unit. KnownMemorySize (MemorySize n metric unit) => Integer
memorySize = knownMemorySize @(MemorySize n metric unit)

{-

import Memory.Metric.SI
type Memory5KB  = MemorySize 5 'Kilo  Word8
testSI  = knownMemorySize @Memory5KB  -- 5000

import Memory.Metric.IEC
type Memory5KiB = MemorySize 5 'Kibi Word8
testIEC = knownMemorySize @Memory5KiB -- 5120
-}
