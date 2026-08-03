"""Statistical analysis of scan behavior."""

from defenderatlas.statistics.compute import compute_statistics
from defenderatlas.statistics.region_statistics import (
    RegionStatistic,
    RegionStatisticsResult,
    compute_region_statistics,
)

__all__ = [
    "RegionStatistic",
    "RegionStatisticsResult",
    "compute_region_statistics",
    "compute_statistics",
]
