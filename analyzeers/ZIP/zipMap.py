#!/usr/bin/env python3

import zipfile
import struct
import csv
import os
import sys

# ============================================================
# Defender Atlas - ZIP Mapper
# Generates a structure map for ZIP archives
# ============================================================

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <zipfile>")
    sys.exit(1)

ZIP_FILE = sys.argv[1]

if not os.path.exists(ZIP_FILE):
    print(f"[!] File not found: {ZIP_FILE}")
    sys.exit(1)

# ============================================================
# Load ZIP
# ============================================================

with open(ZIP_FILE, "rb") as f:
    data = f.read()

file_size = len(data)

print("=" * 80)
print("DEFENDER ATLAS - ZIP STRUCTURE MAPPER")
print("=" * 80)

print(f"\nFile: {ZIP_FILE}")
print(f"Size: {file_size:,} bytes")
print(f"Size: 0x{file_size:X}\n")

regions = []

# ============================================================
# EOCD
# ============================================================

EOCD_SIG = b"\x50\x4B\x05\x06"

eocd_offset = data.rfind(EOCD_SIG)

if eocd_offset == -1:
    print("[!] EOCD not found")
    sys.exit(1)

eocd_end = eocd_offset + 22

eocd = data[eocd_offset:eocd_end]

central_dir_size = struct.unpack("<I", eocd[12:16])[0]
central_dir_offset = struct.unpack("<I", eocd[16:20])[0]

central_dir_end = central_dir_offset + central_dir_size

regions.append({
    "name": "CentralDirectory",
    "start": central_dir_offset,
    "end": central_dir_end
})

regions.append({
    "name": "EOCD",
    "start": eocd_offset,
    "end": eocd_end
})

print("EOCD")
print(f"  Start : 0x{eocd_offset:X}")
print(f"  End   : 0x{eocd_end:X}")
print()

print("Central Directory")
print(f"  Start : 0x{central_dir_offset:X}")
print(f"  End   : 0x{central_dir_end:X}")
print(f"  Size  : {central_dir_size:,}")
print()

# ============================================================
# Entries
# ============================================================

print("=" * 80)
print("ZIP ENTRIES")
print("=" * 80)

with zipfile.ZipFile(ZIP_FILE, "r") as z:

    for idx, info in enumerate(z.infolist(), start=1):

        local_header_start = info.header_offset

        with open(ZIP_FILE, "rb") as f:

            f.seek(local_header_start + 26)

            filename_length = struct.unpack("<H", f.read(2))[0]
            extra_length = struct.unpack("<H", f.read(2))[0]

        local_header_size = 30 + filename_length + extra_length

        local_header_end = local_header_start + local_header_size

        data_start = local_header_end
        data_end = data_start + info.compress_size

        print(f"\n[{idx}] {info.filename}")

        print(
            f"  Header : "
            f"0x{local_header_start:X} -> "
            f"0x{local_header_end:X}"
        )

        print(
            f"  Data   : "
            f"0x{data_start:X} -> "
            f"0x{data_end:X}"
        )

        print(
            f"  Compressed Size   : {info.compress_size:,}"
        )

        print(
            f"  Original Size     : {info.file_size:,}"
        )

        # Region: Header

        regions.append({
            "name": f"LocalHeader::{info.filename}",
            "start": local_header_start,
            "end": local_header_end
        })

        # Region: Data

        regions.append({
            "name": f"FileData::{info.filename}",
            "start": data_start,
            "end": data_end
        })

# ============================================================
# Sort Regions
# ============================================================

regions.sort(key=lambda x: x["start"])

# ============================================================
# Region Table
# ============================================================

print("\n")
print("=" * 80)
print("REGION TABLE")
print("=" * 80)

print(
    f"{'Region':50}"
    f"{'Start':>12}"
    f"{'End':>12}"
    f"{'Size':>12}"
)

print("-" * 86)

for region in regions:

    size = region["end"] - region["start"]

    print(
        f"{region['name'][:50]:50}"
        f"0x{region['start']:08X}"
        f"  "
        f"0x{region['end']:08X}"
        f"  "
        f"{size:10,}"
    )

# ============================================================
# Export CSV
# ============================================================

csv_name = os.path.splitext(os.path.basename(ZIP_FILE))[0]
csv_name += "_regions.csv"

with open(csv_name, "w", newline="") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow([
        "Region",
        "StartDecimal",
        "EndDecimal",
        "StartHex",
        "EndHex",
        "Size"
    ])

    for region in regions:

        writer.writerow([
            region["name"],
            region["start"],
            region["end"],
            hex(region["start"]),
            hex(region["end"]),
            region["end"] - region["start"]
        ])

print("\n")
print("=" * 80)
print("CSV EXPORTED")
print("=" * 80)

print(csv_name)

print("\nDone.")
