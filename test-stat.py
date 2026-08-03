from defenderatlas.parsers import parse_procmon_csv
from defenderatlas.mapping.pe_mapper import PEMapper
from defenderatlas.statistics.region_statistics import compute_region_statistics

events = list(parse_procmon_csv("trace.csv"))

mapper = PEMapper("sample.exe")

mapped_events = mapper.map_events(events)

stats = compute_region_statistics(mapped_events)

print(stats)