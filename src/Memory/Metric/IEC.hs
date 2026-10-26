module Memory.Metric.IEC where

import Memory.Prelude
import Memory.Metric

data IEC = Ubi | Kibi | Mebi | Gibi | Tebi | Pebi | Exbi | Zebi | Yobi

instance MemoryMetric IEC where
    memoryMetricMultiplier Ubi  = 1
    memoryMetricMultiplier Kibi = 2 ^ 10
    memoryMetricMultiplier Mebi = 2 ^ 20
    memoryMetricMultiplier Gibi = 2 ^ 30
    memoryMetricMultiplier Tebi = 2 ^ 40
    memoryMetricMultiplier Pebi = 2 ^ 50
    memoryMetricMultiplier Exbi = 2 ^ 60
    memoryMetricMultiplier Zebi = 2 ^ 70
    memoryMetricMultiplier Yobi = 2 ^ 80

instance KnownMemoryMetric 'Ubi  where proxyMemoryMetric _ = Ubi
instance KnownMemoryMetric 'Kibi where proxyMemoryMetric _ = Kibi
instance KnownMemoryMetric 'Mebi where proxyMemoryMetric _ = Mebi
instance KnownMemoryMetric 'Gibi where proxyMemoryMetric _ = Gibi
instance KnownMemoryMetric 'Tebi where proxyMemoryMetric _ = Tebi
instance KnownMemoryMetric 'Pebi where proxyMemoryMetric _ = Pebi
instance KnownMemoryMetric 'Exbi where proxyMemoryMetric _ = Exbi
instance KnownMemoryMetric 'Zebi where proxyMemoryMetric _ = Zebi
instance KnownMemoryMetric 'Yobi where proxyMemoryMetric _ = Yobi
