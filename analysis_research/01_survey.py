import csv, glob, os, sys
sys.path.insert(0, '/home/godwin/Desktop/000/DefenderAtlas/src')
from collections import Counter
from defenderatlas.parsers.procmon import parse_procmon_csv
from defenderatlas.parsers.errors import CSVFormatError, HeaderError

csv_dir = '/home/godwin/Desktop/000/DefenderAtlas/CSVs/experiment'
print(f"{'exp':<8} {'rows':<7} {'ops':<25} {'results':<30} {'read_events':<12} {'errors':<8}")
for path in sorted(glob.glob(os.path.join(csv_dir, '*_filtered.csv'))):
    eid = os.path.basename(path)[:6]
    # raw row count + op/result distribution (handles quoted commas via csv module)
    ops = Counter(); results = Counter(); rows = 0; parse_errors = 0
    with open(path, newline='', encoding='utf-8-sig') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows += 1
            ops[row.get('Operation','')] += 1
            results[row.get('Result','')] += 1
    try:
        events = list(parse_procmon_csv(path))
    except Exception as e:
        print(f"{eid}: PARSE FAIL {e}")
        continue
    # count parser-skipped rows = read ops - events
    read_op_count = sum(v for k,v in ops.items() if k in ('ReadFile','IRP_MJ_READ','FastIORead'))
    parse_errors = read_op_count - len(events)
    op_str = ','.join(f"{k}:{v}" for k,v in ops.most_common(4))
    res_str = ','.join(f"{k}:{v}" for k,v in results.most_common(3))
    print(f"{eid:<8} {rows:<7} {op_str:<25} {res_str:<30} {len(events):<12} {parse_errors:<8}")
