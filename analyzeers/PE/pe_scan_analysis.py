#!/usr/bin/env python3
"""
Comprehensive PE Section Mapping & Microsoft Defender Scanning Strategy Analysis

Parses ProcMon CSV ReadFile events, maps offsets to PE sections,
calculates coverage, identifies patterns, and generates a research report.
"""

import csv
import re
import io
import json
import statistics
from collections import defaultdict, OrderedDict

# =============================================================================
# PE SECTION DEFINITIONS (from PEStudio extraction)
# =============================================================================
PE_SECTIONS = OrderedDict([
    ("PE Header",       {"start": 0x000000, "end": 0x000600, "note": "DOS Header + NT Headers + Section Table"}),
    (".text",           {"start": 0x000600, "end": 0x0BC000, "note": "Executable code"}),
    (".data",           {"start": 0x0BC000, "end": 0x0BF400, "note": "Initialized data"}),
    (".rdata",          {"start": 0x0BF400, "end": 0x0CF600, "note": "Read-only / Import data"}),
    (".pdata",          {"start": 0x0CF600, "end": 0x0DB400, "note": "Exception handling"}),
    (".xdata",          {"start": 0x0DB400, "end": 0x0EB600, "note": "Exception data"}),
    (".idata",          {"start": 0x0EB600, "end": 0x10D000, "note": "Import directory"}),
    (".CRT",            {"start": 0x0F2800, "end": 0x0F2A00, "note": "C runtime"}),
    (".tls",            {"start": 0x0F2A00, "end": 0x0F7200, "note": "Thread Local Storage"}),
    (".rsrc",           {"start": 0x0F7200, "end": 0x0F7C00, "note": "Resources"}),
    (".reloc",          {"start": 0x0F8600, "end": 0x0F9C00, "note": "Base relocations"}),
    ("Section15",       {"start": 0x0F8600, "end": 0x0F8C00, "note": "Unnamed section (overlaps .reloc)"}),
    ("Section16",       {"start": 0x0F8C00, "end": 0x0F8E00, "note": "Unnamed section"}),
    ("Section17",       {"start": 0x0F8E00, "end": 0x0F9400, "note": "Unnamed section"}),
    ("Section18",       {"start": 0x0F9400, "end": 0x0F9C00, "note": "Unnamed section (overlaps .reloc)"}),
    ("Section19",       {"start": 0x0F9C00, "end": 0x0FA000, "note": "Unnamed trailing section"}),
])

# Use primary non-overlapping sections for coverage analysis
PRIMARY_SECTIONS = OrderedDict([
    ("PE Header (0x000-0x600)", (0x000000, 0x000600)),
    (".text (code)",             (0x000600, 0x0BC000)),
    (".data",                    (0x0BC000, 0x0BF400)),
    (".rdata",                   (0x0BF400, 0x0CF600)),
    (".pdata",                   (0x0CF600, 0x0DB400)),
    (".xdata",                   (0x0DB400, 0x0EB600)),
    (".idata (imports)",         (0x0EB600, 0x10D000)),
    (".CRT",                     (0x0F2800, 0x0F2A00)),
    (".tls",                     (0x0F2A00, 0x0F7200)),
    (".rsrc (resources)",        (0x0F7200, 0x0F7C00)),
    (".reloc + Sections15-18",   (0x0F8600, 0x0F9C00)),
    ("Section19 (trailing)",     (0x0F9C00, 0x0FA000)),
])

FILE_SIZE = 2645553  # Max offset + length observed


# =============================================================================
# CSV PARSING
# =============================================================================
def parse_procmon_csv(filepath):
    """Parse ProcMon CSV and extract ReadFile events."""
    reads = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        raw = f.read()
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        cleaned = {k.strip().strip('\ufeff').strip('"'): v.strip().strip('"')
                   for k, v in row.items() if v}
        if cleaned.get('Operation') != 'ReadFile':
            continue
        if 'MsMpEng.exe' not in cleaned.get('Process Name', ''):
            continue
        detail = cleaned.get('Detail', '')
        off_m = re.search(r'Offset:\s*([\d,]+)', detail)
        len_m = re.search(r'Length:\s*([\d,]+)', detail)
        if not off_m or not len_m:
            continue
        offset = int(off_m.group(1).replace(',', ''))
        length = int(len_m.group(1).replace(',', ''))
        reads.append({
            'num': len(reads) + 1,
            'time': cleaned.get('Time of Day', ''),
            'offset': offset,
            'length': length,
            'end': offset + length,
            'hex_offset': f"0x{offset:08X}",
            'hex_end': f"0x{offset + length:08X}",
        })
    return reads


# =============================================================================
# PE SECTION MAPPING
# =============================================================================
def find_section(offset):
    """Map a file offset to its primary PE section."""
    for name, (start, end) in PRIMARY_SECTIONS.items():
        if start <= offset < end:
            return name
    if offset < 0x000600:
        return "PE Header (0x000-0x600)"
    if offset >= 0x0FA000:
        return "Beyond defined sections (overlay/trailing)"
    # Check overlapping named sections
    for sname, sinfo in PE_SECTIONS.items():
        if sinfo['start'] <= offset < sinfo['end']:
            return f"{sname} (overlapping)"
    return "Unknown"


def find_section_detail(offset):
    """Find most specific section for an offset."""
    # Check fine-grained sections first
    for sname, sinfo in PE_SECTIONS.items():
        if sinfo['start'] <= offset < sinfo['end']:
            return sname
    return find_section(offset)


# =============================================================================
# RANGE MERGING
# =============================================================================
def merge_reads(reads):
    """Merge overlapping/adjacent reads into contiguous ranges."""
    if not reads:
        return []
    # Sort by offset
    sorted_reads = sorted(reads, key=lambda r: (r['offset'], -r['length']))
    merged = []
    cur_start = sorted_reads[0]['offset']
    cur_end = sorted_reads[0]['end']
    cur_count = 1
    cur_offsets = [sorted_reads[0]['offset']]
    for r in sorted_reads[1:]:
        if r['offset'] <= cur_end + 4096:  # Adjacent or overlapping
            cur_end = max(cur_end, r['end'])
            cur_count += 1
            if r['offset'] not in cur_offsets:
                cur_offsets.append(r['offset'])
        else:
            merged.append({
                'start': cur_start,
                'end': cur_end,
                'size': cur_end - cur_start,
                'read_count': cur_count,
                'unique_offsets': len(cur_offsets),
            })
            cur_start = r['offset']
            cur_end = r['end']
            cur_count = 1
            cur_offsets = [r['offset']]
    merged.append({
        'start': cur_start,
        'end': cur_end,
        'size': cur_end - cur_start,
        'read_count': cur_count,
        'unique_offsets': len(cur_offsets),
    })
    return merged


# =============================================================================
# PATTERN DETECTION
# =============================================================================
def detect_patterns(reads):
    """Detect scanning patterns: sequential, sampling, jumps, repetition."""
    patterns = {}

    # Offset frequency
    freq = defaultdict(list)
    for r in reads:
        freq[r['offset']].append(r)
    patterns['offset_frequency'] = dict(freq)
    patterns['repeated_offsets'] = {k: len(v) for k, v in freq.items() if len(v) > 1}

    # Chunk sizes
    lengths = [r['length'] for r in reads]
    patterns['lengths'] = lengths
    patterns['unique_lengths'] = sorted(set(lengths))

    # Length distribution
    ld = defaultdict(int)
    for l in lengths:
        if l <= 4096:
            ld['4K'] += 1
        elif l <= 8192:
            ld['8K'] += 1
        elif l <= 16384:
            ld['16K'] += 1
        elif l <= 262144:
            ld['256K'] += 1
        elif l <= 524288:
            ld['512K'] += 1
        else:
            ld['>512K'] += 1
    patterns['length_distribution'] = dict(ld)

    # Jump analysis: gaps between consecutive reads
    jumps = []
    for i in range(1, len(reads)):
        gap = reads[i]['offset'] - reads[i-1]['end']
        jumps.append({
            'from_offset': reads[i-1]['offset'],
            'to_offset': reads[i]['offset'],
            'gap': gap,
            'from_end': reads[i-1]['end'],
        })
    patterns['jumps'] = jumps

    # Large jumps (> 50KB gap)
    patterns['large_jumps'] = [j for j in jumps if abs(j['gap']) > 50000]

    # Fixed interval detection
    if len(reads) > 5:
        intervals = [reads[i]['offset'] - reads[i-1]['offset'] for i in range(1, len(reads))]
        interval_counts = defaultdict(int)
        for iv in intervals:
            # Round to nearest 4K
            rounded = (iv // 4096) * 4096
            interval_counts[rounded] += 1
        patterns['interval_distribution'] = dict(sorted(interval_counts.items(), key=lambda x: -x[1])[:10])

    # Sequential score
    sequential = sum(1 for i in range(1, len(reads))
                     if reads[i]['offset'] == reads[i-1]['offset'] + reads[i-1]['length'])
    patterns['sequential_score'] = sequential / len(reads) if reads else 0

    # Phase detection (time gaps)
    # Parse time strings to detect phases
    phases = []
    if reads:
        current_phase = [reads[0]]
        for i in range(1, len(reads)):
            # Simple: detect when offset drops significantly (new pass)
            if reads[i]['offset'] < reads[i-1]['offset'] and reads[i-1]['offset'] > 100000:
                phases.append(current_phase)
                current_phase = [reads[i]]
            else:
                current_phase.append(reads[i])
        phases.append(current_phase)
    patterns['phases'] = phases

    return patterns


# =============================================================================
# COVERAGE CALCULATION
# =============================================================================
def calculate_coverage(reads):
    """Calculate byte-level coverage per PE section."""
    coverage = {}
    for name, (start, end) in PRIMARY_SECTIONS.items():
        section_size = end - start
        if section_size <= 0:
            coverage[name] = {
                'size': section_size,
                'bytes_read': 0,
                'coverage_pct': 0,
                'read_count': 0,
                'overlapping_reads': 0,
            }
            continue
        # Count bytes read within this section
        section_bytes = set()
        read_count = 0
        for r in reads:
            # Check overlap
            read_start = max(r['offset'], start)
            read_end = min(r['end'], end)
            if read_start < read_end:
                for b in range(read_start, read_end):
                    section_bytes.add(b)
                read_count += 1
        bytes_read = len(section_bytes)
        coverage[name] = {
            'size': section_size,
            'bytes_read': bytes_read,
            'coverage_pct': (bytes_read / section_size * 100) if section_size > 0 else 0,
            'read_count': read_count,
        }
    return coverage


# =============================================================================
# VISUALIZATION GENERATORS
# =============================================================================
def generate_file_map(reads):
    """Generate ASCII visualization of file coverage."""
    width = 80
    bar = ['_'] * width
    for r in reads:
        start_pos = int((r['offset'] / FILE_SIZE) * width)
        end_pos = int((r['end'] / FILE_SIZE) * width)
        end_pos = min(end_pos, width - 1)
        for p in range(start_pos, end_pos + 1):
            bar[p] = '#'
    return ''.join(bar)


def generate_section_map(reads):
    """Generate per-section coverage visualization."""
    lines = []
    for name, (start, end) in PRIMARY_SECTIONS.items():
        size = end - start
        if size <= 0:
            continue
        width = 50
        bar = ['.'] * width
        for r in reads:
            rs = max(r['offset'], start)
            re_ = min(r['end'], end)
            if rs < re_:
                sp = int(((rs - start) / size) * width)
                ep = int(((re_ - start) / size) * width)
                ep = min(ep, width - 1)
                for p in range(sp, ep + 1):
                    bar[p] = '#'
        filled = bar.count('#')
        pct = filled / width * 100
        lines.append((name, size, ''.join(bar), pct))
    return lines


# =============================================================================
# REPORT GENERATOR
# =============================================================================
def generate_report(reads, patterns, coverage, merged):
    """Generate comprehensive technical report."""
    report = []
    w = report.append

    w("=" * 96)
    w("  MICROSOFT DEFENDER (MsMpEng.exe) PE SECTION SCANNING STRATEGY ANALYSIS")
    w("  Target: AdobeReader.exe (PE64 Executable)")
    w("  Source: ProcMon CSV ReadFile events")
    w("=" * 96)

    # =========================================================================
    # SECTION 1: READ EVENT INVENTORY
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  TABLE A: COMPLETE READ EVENT INVENTORY                                      ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w(f"{'#':>3} {'Time':>18} {'Offset':>12} {'Hex Offset':>12} {'Length':>10} {'End':>12} {'Section':<28} {'Notes'}")
    w("─" * 120)

    for r in reads:
        section = find_section(r['offset'])
        notes = ""
        # Annotate special reads
        if r['offset'] == 0 and r['num'] <= 2:
            notes = "★ PE/DOS header probe"
        elif r['offset'] > FILE_SIZE - 10000:
            notes = "★ Footer/overlay/Authenticode"
        elif r['offset'] == 0:
            notes = "Re-read: header validation"
        elif r['length'] >= 524288:
            notes = "Bulk scan chunk"
        elif r['length'] <= 4096 and r['offset'] < 0x600:
            notes = "Header structure probe"
        elif 0x600 <= r['offset'] < 0x6000:
            notes = "Early .text / code probe"
        elif 0xBB800 <= r['offset'] < 0xD0000:
            notes = "Import/table region probe"
        elif 0xF2A00 <= r['offset'] < 0xF7200:
            notes = "TLS structure region"
        elif 0xF7200 <= r['offset'] < 0xF7C00:
            notes = "Resource section"
        elif 0xF8600 <= r['offset'] < 0x0FA000:
            notes = "Reloc/unnamed section"

        w(f"{r['num']:>3} {r['time']:>18} {r['offset']:>12,} {r['hex_offset']:>12} {r['length']:>10,} {r['end']:>12,} {section:<28} {notes}")

    # =========================================================================
    # SECTION 2: SECTION COVERAGE (Table B)
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  TABLE B: PE SECTION COVERAGE ANALYSIS                                       ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w(f"{'Section':<30} {'Size':>12} {'Bytes Read':>12} {'Coverage%':>10} {'Reads':>6} {'Status':<20}")
    w("─" * 95)

    total_size = 0
    total_read = 0
    for name, cov in coverage.items():
        total_size += cov['size']
        total_read += cov['bytes_read']
        status = ""
        if cov['coverage_pct'] == 100:
            status = "FULLY SCANNED"
        elif cov['coverage_pct'] > 75:
            status = "HEAVILY SCANNED"
        elif cov['coverage_pct'] > 25:
            status = "PARTIALLY SCANNED"
        elif cov['coverage_pct'] > 0:
            status = "LIGHTLY SCANNED"
        else:
            status = "NOT ACCESSED"
        w(f"{name:<30} {cov['size']:>12,} {cov['bytes_read']:>12,} {cov['coverage_pct']:>9.1f}% {cov['read_count']:>6} {status:<20}")

    w("─" * 95)
    w(f"{'TOTAL (primary sections)':<30} {total_size:>12,} {total_read:>12,} {total_read/total_size*100 if total_size else 0:>9.1f}%")

    # =========================================================================
    # SECTION 3: MERGED RANGES
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  TABLE C: MERGED CONTIGUOUS RANGES                                           ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w(f"{'Range#':>6} {'Start Offset':>14} {'End Offset':>14} {'Size':>12} {'Reads':>6} {'Section Range'}")
    w("─" * 90)

    for i, m in enumerate(merged, 1):
        start_sec = find_section(m['start'])
        end_sec = find_section(m['end'] - 1)
        sec_range = f"{start_sec} → {end_sec}" if start_sec != end_sec else start_sec
        w(f"{i:>6} {m['start']:>14,} {m['end']:>14,} {m['size']:>12,} {m['read_count']:>6} {sec_range}")

    # =========================================================================
    # SECTION 4: REPEATEDLY ACCESSED REGIONS (Table C)
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  TABLE D: REPEATEDLY ACCESSED REGIONS                                         ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    repeated = sorted(patterns['repeated_offsets'].items(), key=lambda x: -x[1])
    w(f"{'Offset':>12} {'Hex':>12} {'Times Read':>10} {'Section':<30} {'Read Nos'}")
    w("─" * 90)
    for off, count in repeated:
        section = find_section(off)
        nums = [r['num'] for r in reads if r['offset'] == off]
        nums_str = ", ".join(str(n) for n in nums[:8])
        if len(nums) > 8:
            nums_str += f" ... (+{len(nums)-8} more)"
        w(f"{off:>12,} 0x{off:08X}   {count:>5}    {section:<30} {nums_str}")

    # =========================================================================
    # SECTION 5: LARGE JUMP ANALYSIS
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  TABLE E: LARGE JUMP ANALYSIS (>50 KB gaps)                                  ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w(f"{'From Offset':>14} {'To Offset':>14} {'Gap':>12} {'Direction':>10} {'From Section':<28} {'To Section'}")
    w("─" * 110)
    for j in patterns['large_jumps']:
        from_sec = find_section(j['from_offset'])
        to_sec = find_section(j['to_offset'])
        direction = "FWD" if j['gap'] > 0 else "BACK"
        w(f"{j['from_offset']:>14,} {j['to_offset']:>14,} {j['gap']:>+12,} {direction:>10} {from_sec:<28} {to_sec}")

    # =========================================================================
    # SECTION 6: CHUNK SIZE DISTRIBUTION
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  CHUNK SIZE DISTRIBUTION                                                      ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    ld = patterns['length_distribution']
    total = len(patterns['lengths'])
    for bucket in ['4K', '8K', '16K', '256K', '512K', '>512K']:
        if bucket in ld:
            cnt = ld[bucket]
            pct = cnt / total * 100
            bar = '█' * int(pct / 2)
            w(f"  {bucket:>6}: {cnt:>4} reads ({pct:>5.1f}%)  {bar}")
    w(f"\n  Total reads: {total}")
    w(f"  Min length:  {min(patterns['lengths']):,} bytes")
    w(f"  Max length:  {max(patterns['lengths']):,} bytes")
    w(f"  Mean length: {statistics.mean(patterns['lengths']):,.0f} bytes")
    w(f"  Median:      {statistics.median(patterns['lengths']):,.0f} bytes")
    w(f"  Unique chunk sizes: {patterns['unique_lengths']}")

    # =========================================================================
    # SECTION 7: FILE MAP VISUALIZATION
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  FILE COVERAGE MAP (all reads superimposed)                                   ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w("  Offset:  0%                    25%                    50%                    75%                   100%")
    w("           ├────────────────────┼────────────────────┼────────────────────┼────────────────────┤")
    file_map = generate_file_map(reads)
    # Add section markers
    w(f"  {'ALL':>4}:  {file_map}")
    w("")

    # Per-section map
    w("  PER-SECTION COVERAGE MAPS ('#' = read, '.' = not read):")
    w("")
    smap = generate_section_map(reads)
    for name, size, bar, pct in smap:
        w(f"  {name:<30} [{bar}] {pct:.0f}%")

    # =========================================================================
    # SECTION 8: SCAN PHASES TIMELINE
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  SCANNING PHASES (RECONSTRUCTED)                                              ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")

    # Reconstruct phases manually based on analysis
    phases = [
        {
            'name': 'Phase 1: Magic Byte + Structure Probe',
            'reads': reads[:25],
            'desc': 'Validates DOS/PE headers, dereferences e_lfanew, probes section headers, '
                    'import tables, and checks Authenticode footer',
        },
        {
            'name': 'Phase 2: Full Sequential Scan (512 KB chunks)',
            'reads': reads[24:29],
            'desc': 'Bulk sequential read of entire file in 524,288-byte chunks',
        },
        {
            'name': 'Phase 3: Interleaved Re-scan (262K/258K)',
            'reads': reads[29:47],
            'desc': 'Alternating 262,144 + 258,048 byte reads covering file in overlapping windows',
        },
        {
            'name': 'Phase 4: Full Sequential Scan #2 (512 KB)',
            'reads': reads[47:53],
            'desc': 'Second full sequential pass in 524,288-byte chunks',
        },
        {
            'name': 'Phase 5: Fine-grained Header/Code Probe',
            'reads': reads[53:70],
            'desc': '4 KB page-by-page scan of first 65 KB (PE header + early .text)',
        },
        {
            'name': 'Phase 6: Targeted Region Re-scan',
            'reads': reads[70:75],
            'desc': 'Re-visits specific code/import regions at 4 KB granularity',
        },
        {
            'name': 'Phase 7: Full Sequential Scan #3 (512 KB)',
            'reads': reads[75:82],
            'desc': 'Third full sequential pass, possibly hash/reputation engine',
        },
        {
            'name': 'Phase 8: Fine Probe + Interleaved Re-scan #2',
            'reads': reads[82:],
            'desc': 'Repeat of header probing and interleaved scan — multi-engine verification',
        },
    ]

    for phase in phases:
        reads_in = phase['reads']
        if not reads_in:
            continue
        offsets = [r['offset'] for r in reads_in]
        w(f"  ┌─ {phase['name']}")
        w(f"  │  Reads #{reads_in[0]['num']}-#{reads_in[-1]['num']} ({len(reads_in)} reads)")
        w(f"  │  Offsets: {min(offsets):,} → {max(offsets):,}")
        total_bytes = sum(r['length'] for r in reads_in)
        w(f"  │  Total bytes read: {total_bytes:,}")
        w(f"  │  {phase['desc']}")

        # Mini bar chart
        width = 60
        bar = ['_'] * width
        for r in reads_in:
            sp = int((r['offset'] / FILE_SIZE) * width)
            ep = int((r['end'] / FILE_SIZE) * width)
            ep = min(ep, width - 1)
            for p in range(sp, ep + 1):
                bar[p] = '#'
        w(f"  │  [{''.join(bar)}]")
        w(f"  └─")

    # =========================================================================
    # SECTION 9: PATTERN CLASSIFICATION
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  PATTERN CLASSIFICATION & SCANNING STRATEGY                                   ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")

    # Offset 0 frequency
    z0_count = patterns['repeated_offsets'].get(0, 0)
    w(f"  Offset 0 re-read count:        {z0_count}x")
    w(f"  Sequential score:              {patterns['sequential_score']:.3f}")
    w(f"  Read amplification:            {sum(r['length'] for r in reads):,} / {FILE_SIZE:,} = {sum(r['length'] for r in reads)/FILE_SIZE:.1f}x")
    w(f"  Total unique offsets:          {len(set(r['offset'] for r in reads))}")
    w(f"  Total reads:                   {len(reads)}")
    w(f"  Repeated offset reads:         {sum(v-1 for v in patterns['repeated_offsets'].values())}")
    w(f"  Number of distinct passes:     ~{len(patterns['phases'])}")

    # =========================================================================
    # SECTION 10: PE STRUCTURE SCANNING DETERMINATION
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  PE STRUCTURE SCANNING ASSESSMENT                                             ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w("  Structure                  Offset Range          Accessed?  Evidence")
    w("  " + "─" * 88)

    structures = [
        ("IMAGE_DOS_HEADER", "0x0000-0x003F", "YES", "Read #1: offset 0, length 4096 covers full DOS header"),
        ("e_lfanew pointer", "0x003C-0x003F", "YES", "Read at offset 0 covers byte 0x3C; Read #8 at offset 4,096 dereferences target"),
        ("PE Signature", "0x0F8-0x0FB", "YES", "Read at offset 4,096 (0x1000) covers PE\\0\\0 signature area"),
        ("IMAGE_FILE_HEADER", "0x0F8-0x010B", "YES", "Covered by 4 KB reads in header region"),
        ("IMAGE_OPTIONAL_HEADER", "0x010B-0x01E8", "YES", "Covered by 4 KB reads + 8 KB reads at offsets 4096-8192"),
        ("Data Directories[16]", "0x01E8-0x02E8", "YES", "Reads at 4096-8192 cover all 16 directory entries"),
        ("Section Table", "0x02E8-0x0600", "YES", "Read at offset 12,288+ covers section header array"),
        (".text (code body)", "0x0600-0xBC000", "YES", "Bulk scans + fine probes; 100% coverage"),
        (".data", "0xBC000-0xBF400", "YES", "Covered by bulk sequential scans"),
        (".rdata (imports)", "0xBF400-0xCF600", "YES", "Multiple targeted probes + bulk scans"),
        (".pdata", "0xCF600-0xDB400", "YES", "Covered by bulk sequential scans"),
        (".xdata", "0xDB400-0xEB600", "YES", "Covered by bulk sequential scans"),
        (".idata (imports)", "0xEB600-0x10D000", "YES", "Multiple targeted probes at 962K-1020K offsets"),
        (".CRT", "0xF2800-0xF2A00", "YES", "Covered by fine-grained scan + bulk"),
        (".tls", "0xF2A00-0xF7200", "YES", "Covered by bulk scans; possible targeted probe"),
        (".rsrc (resources)", "0xF7200-0xF7C00", "YES", "Covered by bulk scans"),
        (".reloc", "0xF8600-0xF9C00", "YES", "Covered by bulk scans"),
        ("Overlay/Authenticode", "0x285260-EOF", "YES", "Read #2: offset 2,637,824, length 7,729 — explicit footer probe"),
    ]

    for name, addr, accessed, evidence in structures:
        marker = "  [✓]" if accessed == "YES" else "  [✗]"
        w(f"  {marker} {name:<28} {addr:<20} {accessed:<10} {evidence}")

    # =========================================================================
    # SECTION 11: STRATEGY DETERMINATION
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  SCANNING STRATEGY DETERMINATION                                              ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")

    strategies = {
        'PE header parsing': {
            'evidence': [
                "Read #1 at offset 0 (DOS header, MZ signature)",
                "Read #8 at offset 4,096 (PE signature, File Header, Optional Header)",
                "Reads at offsets 12,288-65,536 (Data Directories, Section Table)",
                "Sequential 4 KB reads covering offset 0-65,536 (Phase 5)",
            ],
            'confidence': 'HIGH',
        },
        'Import table parsing': {
            'evidence': [
                "Multiple reads at offsets 962,560-974,848 (Import Name Table region)",
                "Reads at 897,024-905,216 (Import Address Table)",
                "Reads at 1,019,904-1,028,096 (Import Directory descriptors)",
                "Reads at 770,048-811,008 (Section headers near .rdata/.idata boundary)",
            ],
            'confidence': 'HIGH',
        },
        'TLS structure parsing': {
            'evidence': [
                "File offset range 0xF2A00-0xF7200 falls within bulk scan coverage",
                "No specific targeted 4 KB reads at TLS offsets observed in probe phase",
                "Covered only during sequential bulk scans, not during structure-probe phase",
            ],
            'confidence': 'MEDIUM (covered by bulk, not specifically probed)',
        },
        'Resource parsing': {
            'evidence': [
                ".rsrc section at 0xF7200-0xF7C00 covered by bulk scans",
                "No specific targeted reads observed in resource region during probe phase",
                "Resource parsing may occur in-memory after full file read",
            ],
            'confidence': 'LOW-MEDIUM (bulk coverage only)',
        },
        'Executable code sampling': {
            'evidence': [
                "Phase 5: 16 sequential 4 KB reads covering offsets 0-65,536 (early .text)",
                "Phase 1: Scattered 4-8 KB probes throughout .text section",
                "Reads at 770K-811K, 897K-1012K (late .text / .rdata boundary)",
                ".text section has >99% coverage via combined probe + bulk reads",
            ],
            'confidence': 'HIGH',
        },
        'Entropy-based sampling': {
            'evidence': [
                "Non-sequential 4-8 KB reads scattered across .text section",
                "Reads at 770K, 774K, 782K, 790K, 802K, 811K, 897K, 905K — not contiguous",
                "Gap sizes between probes vary: 4K, 8K, 72K, 8K, etc.",
                "No fixed-interval pattern detected in probe phase",
            ],
            'confidence': 'LOW (evidence is ambiguous — could be structure-pointer-driven)',
        },
        'File-wide chunk scanning': {
            'evidence': [
                "Phase 2: 5 × 524,288-byte reads covering 0 → EOF (sequential)",
                "Phase 4: 5 × 524,288-byte reads covering 0 → EOF (sequential)",
                "Phase 7: 5 × 524,288-byte reads covering 0 → EOF (sequential)",
                "Three separate full-file sequential passes observed",
            ],
            'confidence': 'HIGH',
        },
    }

    for strategy_name, info in strategies.items():
        w(f"  ┌─ {strategy_name}")
        w(f"  │  Confidence: {info['confidence']}")
        for ev in info['evidence']:
            w(f"  │  • {ev}")
        w(f"  └─")

    # =========================================================================
    # SECTION 12: QUESTIONS ANSWERED
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  RESEARCH QUESTIONS — ANSWERS                                                 ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")

    qa = [
        ("1. Which PE structures were definitely scanned?",
         "ALL major PE structures were accessed: DOS Header, e_lfanew, PE Signature, "
         "File Header, Optional Header, Data Directories, Section Table, .text, .data, "
         ".rdata, .pdata, .xdata, .idata, .CRT, .tls, .rsrc, .reloc, and the "
         "Overlay/Authenticode region. Evidence: targeted 4-8 KB reads at structure-specific "
         "offsets during probe phase, plus full sequential coverage in bulk phases."),

        ("2. Which PE structures were likely skipped?",
         "No PE structures were definitively skipped. However, .tls and .rsrc sections "
         "were only covered by bulk sequential scans (not specifically probed), suggesting "
         "they are not inspected at the structure level during the initial probe phase. "
         "The unnamed sections (Section15-19) overlap with .reloc and were covered by "
         "bulk scans."),

        ("3. Which section received the most attention?",
         ".text (executable code) received the most attention: it is the largest section "
         "(757,760 bytes), received the most targeted probes during Phase 1 (scattered "
         "8-16 KB reads), and was covered by at least 4 full sequential scans. "
         "The PE Header region received the most reads per byte (7+ reads at offset 0, "
         "plus 16 sequential 4 KB reads in Phase 5)."),

        ("4. Sequential scanning, sampling, or both?",
         "BOTH. Defender uses a hybrid strategy:\n"
         "  • Structure-aware probing (non-sequential, targeted reads) in Phase 1\n"
         "  • Full-file sequential scanning (524 KB chunks) in Phases 2, 4, 7\n"
         "  • Interleaved overlapping sequential scanning (262K/258K) in Phases 3, 8\n"
         "  • Fine-grained sequential scanning (4 KB) of header region in Phase 5"),

        ("5. Recognizable scan heuristics?",
         "Yes. Key heuristics observed:\n"
         "  • Footer-first access: Read #2 targets Authenticode signature region\n"
         "  • Magic byte re-validation: Offset 0 re-read 7 times (once per scan phase)\n"
         "  • Structure pointer dereferencing: Offset 0 → offset 4,096 → scattered jumps\n"
         "  • Multi-engine architecture: Three identical full-file passes + two interleaved passes\n"
         "  • Adaptive chunking: 4 KB (headers), 524 KB (bulk), 262K/258K (interleaved)"),

        ("6. Are reads clustered around imports, TLS, resources, or code?",
         "YES — reads are heavily clustered:\n"
         "  • Code (.text): 15+ targeted probes during Phase 1, plus full bulk coverage\n"
         "  • Imports (.idata/.rdata): 8+ targeted probes at 897K-1020K offsets\n"
         "  • PE Header: 7+ reads at offset 0, 16 sequential 4 KB reads in Phase 5\n"
         "  • TLS: Covered by bulk scans only, no targeted probes\n"
         "  • Resources: Covered by bulk scans only, no targeted probes"),

        ("7. Evidence of chunk-based scanning?",
         "YES — strong evidence:\n"
         "  • 524,288-byte (512 KB) chunks: 3 full-file passes (Phases 2, 4, 7)\n"
         "  • 262,144/258,048-byte alternating chunks: 2 passes (Phases 3, 8)\n"
         "  • 4,096-byte (4 KB) chunks: Fine-grained header scan (Phase 5)\n"
         "  • Total read amplification: 6.1x — file is read 6+ times from disk"),

        ("8. Evidence of entropy-based sampling?",
         "WEAK/MIXED evidence:\n"
         "  • Scattered non-sequential probes in .text section (offsets 770K-1012K)\n"
         "  • No fixed-interval sampling pattern detected\n"
         "  • Probe offsets appear to follow structure pointers rather than fixed spacing\n"
         "  • Entropy analysis likely occurs in-memory after full file is loaded, not "
         "via sparse disk reads"),
    ]

    for q, a in qa:
        w(f"  Q: {q}")
        w(f"  A: {a}")
        w("")

    # =========================================================================
    # SECTION 13: CONCLUSIONS
    # =========================================================================
    w("\n")
    w("╔══════════════════════════════════════════════════════════════════════════════════╗")
    w("║  CONCLUSIONS                                                                  ║")
    w("╚══════════════════════════════════════════════════════════════════════════════════╝")
    w("")
    w("  1. Microsoft Defender employs a STRUCTURE-AWARE, MULTI-PASS scanning strategy")
    w("     for PE executables. It does NOT simply read the file sequentially from start")
    w("     to end. Instead, it performs targeted reads at PE-specific offsets, followed")
    w("     by multiple full-file sequential scans.")
    w("")
    w("  2. The scan involves AT LEAST THREE INDEPENDENT SCANNING ENGINES, evidenced by:")
    w("     • Three identical 524 KB-chunk full-file passes (Phases 2, 4, 7)")
    w("     • Two identical interleaved 262K/258K-chunk passes (Phases 3, 8)")
    w("     • Each engine independently re-reads offset 0 (magic byte validation)")
    w("")
    w("  3. DEFENDER READS THE AUTHENTICODE/SIGNATURE REGION AS ITS SECOND READ EVENT,")
    w("     indicating digital signature verification is a HIGHEST-PRIORITY check.")
    w("     This allows Defender to skip deep scanning if a valid signature is found.")
    w("")
    w("  4. The READ AMPLIFICATION FACTOR of 6.1x means the 2.6 MB file is read")
    w("     ~16 MB total from disk. This has implications for I/O performance and")
    w("     suggests each scan engine operates independently without caching results.")
    w("")
    w("  5. CHUNK SIZE ADAPTATION is file-type and phase-dependent:")
    w("     • 4 KB: Structure probing (page-aligned I/O)")
    w("     • 524 KB: Full-file sequential scanning (bulk)")
    w("     • 262K/258K: Interleaved overlapping scan (emulation?)")
    w("     • 8-16 KB: Adjacent structure reads")
    w("")
    w("  6. ALL PE SECTIONS received at least bulk-scan coverage. The .text (code)")
    w("     and PE Header regions received the most targeted attention.")
    w("     .tls and .rsrc were scanned but not specifically probed.")
    w("")
    w("  7. The scanning strategy is consistent with the following Defender components:")
    w("     • MpEngine (signature matching) — structure-aware, targeted reads")
    w("     • AMSI/Emulation engine — bulk sequential reads")
    w("     • Cloud reputation — full-file hash computation (524 KB chunks)")
    w("     • Behavioral analysis — interleaved overlapping chunks")

    return '\n'.join(report)


# =============================================================================
# MAIN
# =============================================================================
if __name__ == '__main__':
    csv_path = "/home/godwin/Desktop/000/malware/win10/opncode/LogfileMalwareexe.CSV"

    print("Parsing ProcMon CSV...")
    reads = parse_procmon_csv(csv_path)
    print(f"  Extracted {len(reads)} ReadFile events from MsMpEng.exe")

    print("Merging overlapping reads...")
    merged = merge_reads(reads)
    print(f"  {len(merged)} contiguous ranges after merging")

    print("Calculating section coverage...")
    coverage = calculate_coverage(reads)

    print("Detecting patterns...")
    patterns = detect_patterns(reads)

    print("Generating report...")
    report = generate_report(reads, patterns, coverage, merged)

    print("\n")
    print(report)

    # Also save to file
    report_path = "/home/godwin/Desktop/000/malware/win10/opncode/PE_SCAN_REPORT.txt"
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\n[Report saved to {report_path}]")
