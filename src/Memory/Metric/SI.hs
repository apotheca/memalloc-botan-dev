module Memory.Metric.SI where

import Memory.Prelude
import Memory.Metric

data SI = Unit | Kilo | Mega | Giga | Tera | Peta | Exa | Zetta | Yotta

instance MemoryMetric SI where
    memoryMetricMultiplier Unit  = 1
    memoryMetricMultiplier Kilo  = 10 ^ 3
    memoryMetricMultiplier Mega  = 10 ^ 6
    memoryMetricMultiplier Giga  = 10 ^ 9
    memoryMetricMultiplier Tera  = 10 ^ 12
    memoryMetricMultiplier Peta  = 10 ^ 15
    memoryMetricMultiplier Exa   = 10 ^ 18
    memoryMetricMultiplier Zetta = 10 ^ 21
    memoryMetricMultiplier Yotta = 10 ^ 24

instance KnownMemoryMetric 'Unit  where proxyMemoryMetric _ = Unit
instance KnownMemoryMetric 'Kilo  where proxyMemoryMetric _ = Kilo
instance KnownMemoryMetric 'Mega  where proxyMemoryMetric _ = Mega
instance KnownMemoryMetric 'Giga  where proxyMemoryMetric _ = Giga
instance KnownMemoryMetric 'Tera  where proxyMemoryMetric _ = Tera
instance KnownMemoryMetric 'Peta  where proxyMemoryMetric _ = Peta
instance KnownMemoryMetric 'Exa   where proxyMemoryMetric _ = Exa
instance KnownMemoryMetric 'Zetta where proxyMemoryMetric _ = Zetta
instance KnownMemoryMetric 'Yotta where proxyMemoryMetric _ = Yotta
