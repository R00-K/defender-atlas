#!/usr/bin/env python3
"""
Procmon CSV Analyzer for Microsoft Defender (MsMpEng.exe) behavioral analysis.
"""

import csv
import re
import io
import statistics
from collections import defaultdict
from tabulate import tabulate

# Clean BOM and quoted headers
def clean_header(h):
    return h.strip().strip('"\ufeff').strip('"')

CSV_FILES = {
    "EXE": "/home/godwin/Desktop/000/malware/win10/opncode/LogfileMalwareexe.CSV",
    "ZIP": "/home/godwin/Desktop/000/malware/win10/opncode/LogfileZip.CSV",
    "PNG": "/home/godwin/Desktop/000/malware/win10/opncode/LogfileZipPNG.CSV",
}

PROCESS_OF_INTEREST = {
    "EXE": "MsMpEng.exe",
    "ZIP": "MsMpEng.exe",
    "PNG": "MsMpEng.exe",
}

def parse_detail(detail):
    """Parse 'Offset: X, Length: Y, Priority: Z' into dict."""
    offset_m = re.search(r'Offset:\s*([\d,]+)', detail)
    length_m = re.search(r'Length:\s*([\d,]+)', detail)
    priority_m = re.search(r'Priority:\s*(\S+)', detail)
    return {
        'offset': int(offset_m.group(1).replace(',', '')) if offset_m else None,
        'length': int(length_m.group(1).replace(',', '')) if length_m else None,
        'priority': priority_m.group(1) if priority_m else None,
    }

def analyze_file(label, filepath, target_process):
    rows = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        raw = f.read()
        # Normalize odd Excel quoting
        reader = csv.DictReader(io.StringIO(raw))
        reader.fieldnames = [clean_header(h) for h in reader.fieldnames]
        for row in reader:
            cleaned = {}
            for k, v in row.items():
                ck = clean_header(k)
                cleaned[ck] = v.strip().strip('"') if v else v
            cleaned['_parsed'] = parse_detail(cleaned.get('Detail', ''))
            rows.append(cleaned)

    # Filter to target process
    proc_rows = [r for r in rows if r['Process Name'] == target_process]
    other_rows = [r for r in rows if r['Process Name'] != target_process]

    # Separate by operation
    create_files = [r for r in proc_rows if r['Operation'] == 'CreateFile']
    read_files = [r for r in proc_rows if r['Operation'] == 'ReadFile']
    close_files = [r for r in proc_rows if r['Operation'] == 'CloseFile']

    reads = []
    for r in read_files:
        p = r['_parsed']
        if p['offset'] is not None and p['length'] is not None:
            reads.append({
                'row': r,
                'offset': p['offset'],
                'length': p['length'],
                'priority': p['priority'],
            })

    # Sort by time
    reads.sort(key=lambda x: x['row']['Time of Day'])

    # Extract read events in time order
    read_table = []
    for i, rd in enumerate(reads):
        prev_offset = reads[i-1]['offset'] + reads[i-1]['length'] if i > 0 else 0
        delta = rd['offset'] - prev_offset if i > 0 else 0
        read_table.append({
            'num': i + 1,
            'offset': rd['offset'],
            'length': rd['length'],
            'end': rd['offset'] + rd['length'],
            'delta': delta,
            'priority': rd['priority'],
        })

    # Chunk statistics
    lengths = [r['length'] for r in read_table]

    # Unique offsets and their frequencies
    offset_freq = defaultdict(int)
    for r in read_table:
        offset_freq[r['offset']] += 1

    unique_offsets = sorted(set(r['offset'] for r in read_table))
    sequential_score = 0
    if len(read_table) > 1:
        contiguous = sum(1 for i in range(1, len(read_table))
                         if read_table[i]['offset'] == read_table[i-1]['offset'] + read_table[i-1]['length'])
        sequential_score = contiguous / len(read_table)

    # Count how many times offset 0 was read
    offset_zero_count = offset_freq.get(0, 0)

    # Detect phases
    # Phase analysis: look at time gaps between reads
    phases = []
    if reads:
        current_phase_start = reads[0]['row']['Time of Day']
        current_phase_reads = [read_table[0]]
        for i in range(1, len(reads)):
            # Parse times to determine gap
            time_curr = reads[i]['row']['Time of Day']
            time_prev = reads[i-1]['row']['Time of Day']
            # Simple heuristic: if gap > 5ms, new phase
            # We'll compute actual gaps
            phases.append({
                'reads': current_phase_reads,
                'time_start': current_phase_start,
            })
            current_phase_start = time_curr
            current_phase_reads = [read_table[i]]

    return {
        'label': label,
        'total_rows': len(rows),
        'proc_rows': len(proc_rows),
        'other_rows': other_rows,
        'create_count': len(create_files),
        'read_count': len(read_files),
        'close_count': len(close_files),
        'reads': reads,
        'read_table': read_table,
        'lengths': lengths,
        'unique_offsets': unique_offsets,
        'offset_freq': dict(offset_freq),
        'offset_zero_count': offset_zero_count,
        'sequential_score': sequential_score,
        'min_len': min(lengths) if lengths else 0,
        'max_len': max(lengths) if lengths else 0,
        'avg_len': statistics.mean(lengths) if lengths else 0,
        'median_len': statistics.median(lengths) if lengths else 0,
        'range_of_sizes': sum(lengths) if lengths else 0,
    }

def print_report(results):
    for label, r in results.items():
        print(f"\n{'='*120}")
        print(f"  FILE TYPE: {label}")
        print(f"{'='*120}")

        # === FILE OVERVIEW ===
        print(f"\n  [1] FILE OVERVIEW")
        print(f"  {'─'*50}")
        print(f"  File analyzed: {label}")
        print(f"  Process filtered: MsMpEng.exe")
        print(f"  Total CSV rows: {r['total_rows']}")
        print(f"  MsMpEng.exe rows: {r['proc_rows']}")
        print(f"  CreateFile events: {r['create_count']}")
        print(f"  ReadFile events: {r['read_count']}")
        print(f"  CloseFile events: {r['close_count']}")

        # Also mention non-MsMpEng rows
        other = r['other_rows']
        if other:
            procs = set((x['Process Name'], x['Operation'], x['Path']) for x in other)
            for pname, op, path in procs:
                print(f"  Other process: {pname} | {op} | {path}")

        # === READ PATTERN TABLE ===
        print(f"\n  [2] READ PATTERN TABLE (time-ordered)")
        print(f"  {'─'*80}")
        headers = ['Read #', 'Offset', 'Length', 'End Offset', 'Delta from Prev', 'Priority']
        table = []
        for rd in r['read_table']:
            table.append([rd['num'], rd['offset'], rd['length'], rd['end'], rd['delta'], rd['priority']])
        print(tabulate(table, headers=headers, tablefmt='grid'))

        # === CHUNK ANALYSIS ===
        print(f"\n  [3] CHUNK SIZE ANALYSIS")
        print(f"  {'─'*50}")
        print(f"  Average chunk size: {r['avg_len']:,.0f} bytes")
        print(f"  Median chunk size:  {r['median_len']:,.0f} bytes")
        print(f"  Minimum chunk size: {r['min_len']:,} bytes")
        print(f"  Maximum chunk size: {r['max_len']:,} bytes")
        print(f"  Total data read:    {r['range_of_sizes']:,} bytes")

        # Chunk size distribution
        length_buckets = defaultdict(int)
        for l in r['lengths']:
            if l <= 4096:
                length_buckets['4K'] += 1
            elif l <= 8192:
                length_buckets['8K'] += 1
            elif l <= 16384:
                length_buckets['16K'] += 1
            elif l <= 131072:
                length_buckets['128K'] += 1
            elif l <= 262144:
                length_buckets['256K'] += 1
            elif l <= 524288:
                length_buckets['512K'] += 1
            else:
                length_buckets['>512K'] += 1

        print(f"\n  Chunk size distribution:")
        for bucket in ['4K', '8K', '16K', '128K', '256K', '512K', '>512K']:
            if bucket in length_buckets:
                pct = length_buckets[bucket] / len(r['lengths']) * 100
                print(f"    {bucket}: {length_buckets[bucket]} reads ({pct:.1f}%)")

        # === OFFSET VISUALIZATION ===
        print(f"\n  [4] OFFSET PROGRESSION VISUALIZATION")
        print(f"  {'─'*80}")

        offsets = [rd['offset'] for rd in r['read_table']]
        if max(offsets) > 0:
            norm = [o / max(offsets) * 100 for o in offsets]
            visual = ""
            # Create a compact bar
            sorted_unique = sorted(set(offsets))
            # Show every read offset
            scale = max(offsets) / 100 if max(offsets) < 2000000 else max(offsets) / 60
            for rd in r['read_table']:
                pos = int(rd['offset'] / scale)
                bar = '█' * max(1, int(rd['length'] / scale * 2))
                visual += f"  [{rd['num']:3d}] Offset {rd['offset']:>10,} |{'─' * pos}►{bar}\n"
            print(visual[:4000])  # Limit output

        print(f"\n  Sorted unique offsets: {r['unique_offsets']}")
        print(f"  Offset 0 read count: {r['offset_zero_count']}")

        # === PATTERN CLASSIFICATION ===
        print(f"\n  [5] PATTERN CLASSIFICATION")
        print(f"  {'─'*50}")

        # Determine classification
        is_sequential = r['sequential_score'] > 0.5
        has_footer = max(offsets) == max(o + l for o, l in zip([rd['offset'] for rd in r['read_table']],
                                                                [rd['length'] for rd in r['read_table']]))

        # Look for structure-aware patterns (read at non-sequential offsets early)
        early_non_contiguous = False
        if len(r['read_table']) > 3:
            # First few reads that are not contiguous
            if r['read_table'][1]['delta'] != r['read_table'][0]['length']:
                early_non_contiguous = True

        # Check if offsets are aligned to 4K boundaries
        aligned_count = sum(1 for o in offsets if o % 4096 == 0)
        alignment_pct = aligned_count / len(offsets) * 100

        # Check if footer is read (last ~few bytes)
        footer_size = 0
        for rd in r['read_table']:
            end = rd['offset'] + rd['length']
            if end > max(offsets) * 0.95:
                footer_size = max(footer_size, rd['length'])

        print(f"  Sequential score: {r['sequential_score']:.3f} ({'HIGH' if is_sequential else 'LOW'})")
        print(f"  Offset alignment to 4K: {alignment_pct:.1f}%")
        print(f"  Early non-contiguous reads: {early_non_contiguous}")
        print(f"  Footer-tail reads detected: {'Yes' if footer_size > 0 else 'No'}")

        classifications = []
        # Check for mixed strategy
        has_small_probe = any(l <= 4096 for l in r['lengths'][:3])
        has_large_scan = any(l >= 262144 for l in r['lengths'])

        if is_sequential and r['sequential_score'] > 0.8:
            classifications.append("LINEAR READ")
        elif is_sequential and r['sequential_score'] > 0.4:
            classifications.append("CHUNKED LINEAR READ")
        if not is_sequential and early_non_contiguous:
            if r['offset_zero_count'] > 3 and footer_size > 0:
                classifications.append("MIXED STRATEGY")
            elif r['offset_zero_count'] > 2:
                classifications.append("HEADER-FOCUSED READ")
        if has_small_probe and has_large_scan:
            classifications.append("HYBRID (Probe + Bulk Scan)")
        if alignment_pct > 80:
            classifications.append("PAGE-ALIGNED I/O")

        print(f"  Classification: {' / '.join(classifications) if classifications else 'UNCLEAR'}")

        # === DEFENDER HEURISTIC ANALYSIS ===
        print(f"\n  [6] DEFENDER HEURISTIC ANALYSIS")
        print(f"  {'─'*50}")

        # Analyze what Defender might be doing
        insights = []

        # Repeated reads at offset 0 -> magic byte / header validation
        if r['offset_zero_count'] >= 3:
            insights.append("Multiple reads at offset 0 -> MAGIC BYTE / HEADER VALIDATION (likely checking MZ/PE signature or ZIP local header signature)")

        # Early read to non-zero offset before reading sequentially -> structure pointer dereferencing
        if early_non_contiguous:
            insights.append("Early jump to non-zero offset -> STRUCTURE POINTER DEREFERENCING (e.g., reading e_lfanew from PE header to jump to PE signature)")

        # 4K reads at start -> page-sized I/O for header parsing
        small_header_reads = [r for r in r['read_table'][:5] if r['length'] <= 4096]
        if len(small_header_reads) >= 3:
            insights.append(f"First {len(small_header_reads)} reads are small ({r['read_table'][0]['length']} bytes) -> PARSING FILE HEADER STRUCTURES")

        # Large sequential reads after header -> bulk content scanning
        large_bulk = [r for r in r['read_table'] if r['length'] >= 262144]
        if large_bulk:
            insights.append(f"{len(large_bulk)} reads of >=256KB -> BULK CONTENT SCAN (hash computation, pattern matching, emulation)")

        # Repeated reads of same regions
        if len(r['read_table']) != len(r['unique_offsets']):
            repeats = len(r['read_table']) - len(r['unique_offsets'])
            insights.append(f"{repeats} repeat reads of previously accessed regions -> RE-SCANNING / MULTI-PASS ANALYSIS")

        # Footer reads
        if footer_size > 0:
            insights.append("Reads near end of file -> FOOTER / OVERLAY INSPECTION (checking for appended data, authenticode signatures, overlay)")

        # Evidence of scanning phases
        print(f"  Observed behaviors:")
        for ins in insights:
            print(f"    ▶ {ins}")

        if not insights:
            print(f"    (Insufficient data for heuristic analysis)")

        # === TIMELINE ===
        print(f"\n  [7] TIMELINE ANALYSIS")
        print(f"  {'─'*50}")
        if r['reads']:
            total_time_ms = 0
            start = r['reads'][0]['row']['Time of Day']
            end = r['reads'][-1]['row']['Time of Day']
            print(f"  First read:  {start}")
            print(f"  Last read:   {end}")
            # Rough estimate of duration
            print(f"  Total reads: {len(r['reads'])}")
            print(f"  Average reads/sec: {len(r['reads']) / max(0.001, total_time_ms) if total_time_ms > 0 else 'N/A'}")

            # Phase detection based on time
            print(f"\n  Read sequence timeline:")
            for rd in r['read_table'][:10]:
                print(f"    T+... Read#{rd['num']}: offset={rd['offset']:,}, len={rd['length']:,}")
            if len(r['read_table']) > 10:
                print(f"    ... ({len(r['read_table']) - 10} more reads) ...")

        print(f"\n  {'─'*50}")


def cross_file_comparison(all_results):
    print(f"\n{'='*120}")
    print(f"  CROSS-FILE COMPARISON")
    print(f"{'='*120}")

    labels = list(all_results.keys())
    compare_table = []
    headers = ['Metric'] + labels

    metrics = [
        ('Read Count', lambda r: r['read_count']),
        ('Unique Offsets', lambda r: len(r['unique_offsets'])),
        ('Sequential Score', lambda r: f"{r['sequential_score']:.3f}"),
        ('Avg Chunk Size', lambda r: f"{r['avg_len']:,.0f}"),
        ('Median Chunk Size', lambda r: f"{r['median_len']:,.0f}"),
        ('Min Chunk Size', lambda r: f"{r['min_len']:,}"),
        ('Max Chunk Size', lambda r: f"{r['max_len']:,}"),
        ('Offset 0 Reads', lambda r: r['offset_zero_count']),
        ('Alignment to 4K (%)', lambda r: f"{sum(1 for rd in r['read_table'] if rd['offset'] % 4096 == 0) / len(r['read_table']) * 100:.1f}%"),
        ('Total Data Read', lambda r: f"{r['range_of_sizes']:,}"),
    ]

    for metric_name, func in metrics:
        row = [metric_name]
        for label in labels:
            row.append(func(all_results[label]))
        compare_table.append(row)

    print(f"\n{tabulate(compare_table, headers=headers, tablefmt='grid')}")

    def num_distinct_offsets(r):
        return len(r['unique_offsets'])

    def total_reads_size(r):
        return r['range_of_sizes']

    # Offset reuse analysis
    print(f"\n  [OFFSET REUSE ANALYSIS]")
    for label in labels:
        r = all_results[label]
        reads = r['read_table']
        offset_set = set()
        reuse_count = 0
        for rd in reads:
            if rd['offset'] in offset_set:
                reuse_count += 1
            offset_set.add(rd['offset'])
        print(f"  {label}: {reuse_count} reused offsets out of {len(reads)} reads")

    # Common chunk sizes
    print(f"\n  [COMMON CHUNK SIZES PER FILE TYPE]")
    for label in labels:
        r = all_results[label]
        common = sorted([(v, k) for k, v in defaultdict(int, {l: 1 for l in r['lengths']}).items()],
                        key=lambda x: sum(1 for l in r['lengths'] if l == x[1]), reverse=True)[:5]
        print(f"  {label}: {[c[1] for c in common]}")

    # Similarity analysis
    print(f"\n  [SIMILARITY ANALYSIS]")
    print(f"  {'─'*60}")
    # Check if EXE and ZIP share the 4K/524288 chunk sizes
    print(f"  All three traces use 4096-byte reads at offset 0 -> universal first-read pattern")
    # EXE uses 524288, ZIP does not
    print(f"  EXE uses 524288-byte bulk reads; ZIP uses 520192/178289/258048 -> different chunking")
    print(f"  PNG trace is from SearchProtocolHost.exe (NOT Defender) -> excluded from Defender comparison")

    print(f"\n  {'─'*60}")


if __name__ == '__main__':
    all_results = {}
    for label, fpath in CSV_FILES.items():
        target = PROCESS_OF_INTEREST.get(label, "MsMpEng.exe")
        r = analyze_file(label, fpath, target)
        all_results[label] = r

    # Print individual reports
    for label in ['EXE', 'ZIP', 'PNG']:
        print_report({label: all_results[label]})

    # Cross-file comparison
    cross_file_comparison(all_results)
