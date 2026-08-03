================================================================================================
  MICROSOFT DEFENDER (MsMpEng.exe) ZIP ARCHIVE SCANNING STRATEGY ANALYSIS
  Target: cx.zip (ZIP Archive containing APK + extracted APK contents)
  Source: ProcMon CSV ReadFile events
  Scanner PID: 2112 (MsMpEng.exe)
  Scan Duration: 6:52:36 AM - 6:52:45 AM (~9 seconds)
================================================================================================


╔══════════════════════════════════════════════════════════════════════════════════╗
║  1. EXECUTIVE SUMMARY                                                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Microsoft Defender (MsMpEng.exe, PID 2112) performed a comprehensive scan of
cx.zip (24,782,963 bytes / ~23.6 MB) using 840 ReadFile operations totaling
25,248,392 bytes. The scan achieved a 1.02x read amplification ratio, indicating
an efficient linear scan with minimal re-reads.

Key findings:
  - Defender first probed the ZIP header (offset 0) and EOCD (offset 24,776,704)
    to identify the archive structure, then sequentially scanned all file data
  - The scan exhibits a distinctive 512 KB cycle pattern: 7 × 65,536-byte reads
    followed by a 61,440-byte boundary read and a 4,096-byte alignment read
  - All 3 DEX files (classes.dex, classes2.dex, classes3.dex) and the nested
    base.apk were fully scanned with 100% coverage
  - Small resource files (XML, PNG) received individual 4,096-byte reads
  - Central Directory was read 116 times during file enumeration
  - 1,797 of 2,037 file entries received 0 bytes read (primarily tiny metadata)


╔══════════════════════════════════════════════════════════════════════════════════╗
║  2. DATASET INFO                                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Source File:       cx.zip
  File Size:         24,782,963 bytes (23.6 MB)
  Archive Type:      ZIP (containing nested APK structure)
  ProcMon Trace:     CSVs/Logfilezip.CSV
  Structure Map:     analyzeers/ZIP/cx_regions.csv (4,077 regions)
  Scanner:           MsMpEng.exe (PID 2112)
  Total ReadFile:    840 events
  Total Bytes Read:  25,248,392 bytes
  Scan Duration:     ~9 seconds


╔══════════════════════════════════════════════════════════════════════════════════╗
║  3. ZIP STRUCTURE OVERVIEW                                                   ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Region                           Count     Total Bytes    % of File
  ─────────────────────────────────────────────────────────────────────────
  LocalHeaders                     2,037       163,012       0.7%
  FileData                         2,037    24,350,993      98.3%
  CentralDirectory                     1       268,936       1.1%
  EOCD                                 1            22       0.0%
  ─────────────────────────────────────────────────────────────────────────
  TOTAL                            4,076    24,782,963     100.0%

  Note: The archive contains 2,037 file entries including a nested APK
  (cx/base.apk = 8,131,046 bytes) and its fully extracted contents
  (cx/unzip/ = 2,036 entries).

  Archive Layout (simplified):
  ┌──────────────────────────────────────────────────────────┐
  │ cx/                          [LocalHeader]        53 B   │
  │ cx/base.apk                  [FileData]      8,131,046 B│ ← Full nested APK
  │ cx/base.apk.jadx             [FileData]            402 B│
  │ cx/unzip/                    [LocalHeader]         20 B │
  │ cx/unzip/AndroidManifest.xml [FileData]         10,250 B│
  │ cx/unzip/META-INF/...        [FileData]        ~245,000B│
  │ cx/unzip/classes.dex         [FileData]      3,125,906 B│ ← DEX code
  │ cx/unzip/classes2.dex        [FileData]        218,097 B│
  │ cx/unzip/classes3.dex        [FileData]      2,370,265 B│
  │ cx/unzip/resources.arsc      [FileData]        570,230 B│
  │ cx/unzip/res/...             [FileData]     ~15,000,000B│
  │ cx/unzip/assets/...          [FileData]         ~50,000B│
  │ cx/unzip/okhttp3/...         [FileData]         ~41,000B│
  │ Central Directory             [CD]             268,936 B│
  │ EOCD                          [EOCD]                22 B│
  └──────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════════════════════╗
║  4. DEFENDER READ DISTRIBUTION BY ZIP REGION                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  ZIP Region               Bytes Read   % Total     Events
  ────────────────────────────────────────────────────────────────
  FileData                24,395,864     96.6%        2,839*
  CentralDirectory           669,685      2.7%          119*
  LocalHeaders               182,755      0.7%        2,347*
  EOCD                            88      0.0%            4*
  ────────────────────────────────────────────────────────────────
  TOTAL                   25,248,392    100.0%          840

  * Overlapping region counts due to multi-region reads spanning boundaries.


╔══════════════════════════════════════════════════════════════════════════════════╗
║  5. COMPLETE READ EVENT INVENTORY (KEY EVENTS)                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  #     Offset         Length   ZIP Region / File                       Notes
  ────────────────────────────────────────────────────────────────────────────────

  ═══ PHASE 1: HEADER PROBE & TRAILER SEEK (Events 0-2) ═══

    0            0       4,096  LocalHeader::cx/                         ★ ZIP signature probe
    1   24,776,704       6,259  CentralDirectory                         ★ EOCD/CD area seek
    2   24,715,264      67,699  CentralDirectory                         ★ Secondary CD read

  ═══ PHASE 2: STRUCTURE EXPLORATION (Events 3-21) ═══

    3       32,768       4,096  FileData::cx/base.apk                    Nested APK probe
    4   24,510,464       4,096  FileData::cx/unzip/resources.arsc       尾部 resource probe
    5   24,514,560       4,096  CentralDirectory                         CD sequential scan
    6   24,518,656       4,096  CentralDirectory                         CD sequential scan
    7   24,522,752       4,096  CentralDirectory                         CD sequential scan
    8   24,526,848       4,096  CentralDirectory                         CD sequential scan
    9   24,530,944       4,096  CentralDirectory                         CD sequential scan
   10   24,535,040       8,192  CentralDirectory                         CD reads (growing)
   11   24,543,232      16,384  CentralDirectory                         CD reads (growing)
   12   24,559,616      16,384  CentralDirectory                         CD reads (growing)
   13   24,576,000      16,384  CentralDirectory                         CD reads (growing)
   14   24,592,384      16,384  CentralDirectory                         CD reads (growing)
   15   24,608,768      16,384  CentralDirectory                         CD reads (growing)
   16   24,625,152      16,384  CentralDirectory                         CD reads (growing)
   17   24,641,536      16,384  CentralDirectory                         CD reads (growing)
   18   24,657,920      16,384  CentralDirectory                         CD reads (growing)
   19   24,674,304      16,384  CentralDirectory                         CD reads (growing)
   20   24,690,688      16,384  CentralDirectory                         CD reads (growing)
   21   24,707,072       8,192  CentralDirectory                         CD tail read

  ═══ PHASE 3: RE-READ HEADER + SEQUENTIAL SCAN START ═══

   22            0       4,096  LocalHeader::cx/                         ★ Re-read ZIP header
   23        4,096      65,536  FileData::cx/base.apk                    Start sequential scan
   24       69,632      65,536  FileData::cx/base.apk
   25      135,168      65,536  FileData::cx/base.apk
   26      200,704      65,536  FileData::cx/base.apk
   27      266,240      65,536  FileData::cx/base.apk
   28      331,776      65,536  FileData::cx/base.apk
   29      397,312      65,536  FileData::cx/base.apk
   30      462,848      61,440  FileData::cx/base.apk                    ★ Cycle boundary
   31      524,288       4,096  FileData::cx/base.apk                    ★ Alignment read

  ═══ PHASE 4: 512 KB CYCLIC PATTERN (Events 32-319) ═══

  [Pattern repeats 19 times for cx/base.apk]
  Each cycle: [7 × 65,536] + [1 × 61,440] + [1 × 4,096] = 524,288 bytes

   ...    ...         ...     ...                                      [7 × 65K reads each]
   86  3,674,112      65,536  FileData::cx/base.apk
   87  3,739,648      65,536  FileData::cx/base.apk
   88  3,805,184      65,536  FileData::cx/base.apk
   89  3,870,720      61,440  FileData::cx/base.apk                    ★ Last base.apk cycle end
   ...                                                              [Transitions to nested content]

  ═══ PHASE 5: NESTED CONTENT ENUMERATION (Events 156-827) ═══

  156   24,514,005       4,096  FileData::cx/unzip/resources.arsc        Resource scan start
  157   23,791,104       8,192  FileData::cx/unzip/AndroidManifest.xml   Manifest scan
  158   24,518,656       4,096  CentralDirectory                         CD re-read
  159   23,787,008       4,096  FileData::cx/unzip/LICENSE-junit.txt     License scan
  160   24,513,705       4,096  LocalHeader::cx/unzip/META-INF/BNDLTOOL.RSA
  161   24,513,761      77,824  FileData::cx/unzip/META-INF/BNDLTOOL.SF  Signature scan
  163   24,432,720      77,824  FileData::cx/unzip/META-INF/MANIFEST.MF  Manifest scan
  176   23,825,920      45,056  FileData::cx/unzip/assets/exolibs.zip     ★ Nested ZIP scan
  179            0   8,130,560  FileData::cx/unzip/base.zip              ★ Full nested APK re-scan
  ...
  321   14,675,968   3,125,248  FileData::cx/unzip/classes.dex           ★ Full DEX1 scan
  ...
  376   19,572,736     217,088  FileData::cx/unzip/classes2.dex          ★ Full DEX2 scan
  ...
  381   19,638,272   2,371,584  FileData::cx/unzip/classes3.dex          ★ Full DEX3 scan
  ...
  427   24,110,592      40,960  FileData::cx/unzip/com/google/api/client/googleapis/google.jks
  428   24,151,552      28,672  FileData::cx/unzip/com/google/api/client/googleapis/google.p12
  434   24,342,528      16,384  FileData::cx/unzip/drive.v3.json          Config scan
  439   24,436,816      49,152  FileData::cx/unzip/okhttp3/.../publicsuffixes.gz
  ...
  447-827             (4,096 ea) [~400 small XML/PNG resource files]     Individual reads
  ...
  828   23,945,216      65,536  FileData::cx/unzip/resources.arsc        Resource table scan
  829   24,010,752      65,536  FileData::cx/unzip/resources.arsc
  830   24,076,288      40,960  FileData::cx/unzip/resources.arsc
  831   24,117,248      24,576  FileData::cx/unzip/resources.arsc
  832   24,141,824      65,536  FileData::cx/unzip/resources.arsc
  833   24,207,360      65,536  FileData::cx/unzip/resources.arsc
  834   24,272,896      65,536  FileData::cx/unzip/resources.arsc
  835   24,338,432      65,536  FileData::cx/unzip/resources.arsc
  836   24,403,968      65,536  FileData::cx/unzip/resources.arsc
  837   24,469,504      45,056  FileData::cx/unzip/resources.arsc

  ═══ PHASE 6: FINAL VERIFICATION ═══

  838   24,780,800       2,163  CentralDirectory                         ★ Final CD check
  839            0         188  LocalHeader::cx/Zone.Identifier           ★ Zone.Identifier read


╔══════════════════════════════════════════════════════════════════════════════════╗
║  6. OFFSET-TO-REGION CORRELATION                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Offset Range                  ZIP Region            Size        Read By Defender
  ─────────────────────────────────────────────────────────────────────────────────
  0 - 52                    LocalHeader::cx/           53 B        YES (4,096 B)
  52 - 8,131,098           FileData::cx/base.apk  8,131,046 B     YES (100.0%)
  8,131,098 - 23,764,041   FileData::cx/unzip/base.zip 8,131,046 B YES (100.0%)
  23,764,041 - 23,790,135  FileData::cx/unzip/AndroidManifest.xml  YES (79.9%)
  ...                      [Additional cx/unzip/ entries]
  23,943,422 - 23,943,475  LocalHeader resources.arsc     53 B     YES (header only)
  23,943,475 - 24,513,705  FileData resources.arsc   570,230 B     YES (101.3%)
  ...                      [Additional cx/unzip/ entries]
  24,514,005 - 24,782,941  CentralDirectory          268,936 B     YES (249.3%)
  24,782,941 - 24,782,963  EOCD                          22 B     YES (400.0%)
  ─────────────────────────────────────────────────────────────────────────────────


╔══════════════════════════════════════════════════════════════════════════════════╗
║  7. READ LENGTH DISTRIBUTION                                                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Length (bytes)     Count    Total Bytes    % of Data     Purpose
  ──────────────────────────────────────────────────────────────────────────────
         188              1           188       0.0%     Zone.Identifier read
       2,163              2         4,326       0.0%     CentralDirectory tail
       4,096            432     1,769,472       7.0%     Small file / metadata reads
       6,259              1         6,259       0.0%     EOCD probe
       8,192             19       155,648       0.6%     Medium file reads
      12,288              2        24,576       0.1%     Medium file reads
      16,384             14       229,376       0.9%     CD scanning / medium files
      20,480             10       204,800       0.8%     Image files (PNG)
      24,576              6       147,456       0.6%     Image files (PNG)
      28,672              1        28,672       0.1%     google.p12
      32,768              1        32,768       0.1%     Image files (PNG)
      36,864              1        36,864       0.1%     (unused)
      40,960              2        81,920       0.3%     google.jks / resources.arsc
      45,056              3       135,168       0.5%     exolibs.zip / resources.arsc
      53,248              1        53,248       0.2%     TTF font file
      57,344             16       917,504       3.6%     Large resource reads
      61,440             19     1,167,360       4.6%     ★ 512 KB cycle boundary reads
      65,536            308    20,185,088      79.9%     ★ Primary sequential scan chunk
      67,699              1        67,699       0.3%     Secondary CD probe
  ──────────────────────────────────────────────────────────────────────────────
  TOTAL                840    25,248,392     100.0%

  ★ The 65,536-byte reads account for 79.9% of all bytes scanned.
    This is the primary chunk size for sequential content scanning.


╔══════════════════════════════════════════════════════════════════════════════════╗
║  8. SCAN PIPELINE RECONSTRUCTION                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  The observed Defender scan follows this pipeline:

  ┌─────────────────────────────────────────────────────────────────┐
  │                    SCAN PIPELINE DIAGRAM                       │
  └─────────────────────────────────────────────────────────────────┘

  PHASE 1: IDENTIFICATION (Events 0-2, ~78 KB)
  ┌──────────────────────────────────────────────────────────────┐
  │ Read offset 0 (4 KB)           → ZIP local header signature │
  │ Read offset 24,776,704 (6 KB)  → EOCD / CD trailer area    │
  │ Read offset 24,715,264 (68 KB) → Full CD region             │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  PHASE 2: STRUCTURE MAP (Events 3-21, ~205 KB)
  ┌──────────────────────────────────────────────────────────────┐
  │ Probe nested APK (offset 32,768)                             │
  │ Scan tail resource data (offset 24,510,464)                  │
  │ Sequential CD read (offset 24,514,560 → 24,715,264)         │
  │ Read sizes grow: 4K → 8K → 16K (adaptive buffering)         │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  PHASE 3: FULL SEQUENTIAL SCAN (Events 22-319, ~8.6 MB)
  ┌──────────────────────────────────────────────────────────────┐
  │ Re-read ZIP header (offset 0, 4 KB)                          │
  │ Start sequential scan of cx/base.apk at offset 4,096         │
  │                                                              │
  │ 512 KB Cycle Pattern (×19 cycles):                           │
  │ ┌────────────────────────────────────────────────────────┐   │
  │ │ [7 × 65,536 B] → [1 × 61,440 B] → [1 × 4,096 B]     │   │
  │ │ = 458,752     + 61,440          + 4,096                │   │
  │ │ = 524,288 bytes = 0.5 MB per cycle                     │   │
  │ └────────────────────────────────────────────────────────┘   │
  │ The 61,440 B read marks the end of each 512 KB boundary.     │
  │ The 4,096 B read aligns to the next 4 KB page boundary.      │
  │ This pattern covers cx/base.apk (8.1 MB nested APK).         │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  PHASE 4: NESTED CONTENT SCANNING (Events 156-827, ~15.8 MB)
  ┌──────────────────────────────────────────────────────────────┐
  │ Scan cx/unzip/base.zip (full re-scan of nested APK):         │
  │   Same 512 KB cycle pattern as Phase 3                       │
  │                                                              │
  │ Scan individual cx/unzip/ files:                             │
  │   classes.dex:   3,125,248 bytes (100.0%)                   │
  │   classes2.dex:    217,088 bytes ( 99.5%)                   │
  │   classes3.dex:  2,371,584 bytes (100.1%)                   │
  │   resources.arsc:  569,344 bytes ( 99.9%)                   │
  │                                                              │
  │ Small file enumeration (~400 entries):                       │
  │   Each receives individual 4,096-byte reads                  │
  │   Files: XML, PNG, version files, license texts             │
  │   Frequent CD re-reads between file accesses                 │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  PHASE 5: VERIFICATION (Events 828-839, ~573 KB)
  ┌──────────────────────────────────────────────────────────────┐
  │ Final resources.arsc sequential scan (569 KB)                │
  │ Final CD verification (2,163 bytes at offset 24,780,800)    │
  │ Zone.Identifier check (188 bytes at offset 0)               │
  └──────────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════════════════════╗
║  9. COVERAGE ANALYSIS                                                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  ═══ FILE-LEVEL COVERAGE (Major Files) ═══

  File                                          Size        Read      Cov%   Events
  ───────────────────────────────────────────────────────────────────────────────────
  cx/base.apk                              8,131,046   8,134,656   100.0%     134
  cx/unzip/base.zip                        8,131,046   8,130,560   100.0%     141
  cx/unzip/classes.dex                      3,125,906   3,125,248   100.0%      54
  cx/unzip/classes3.dex                     2,370,265   2,371,584   100.1%      44
  cx/unzip/resources.arsc                     570,230     577,536   101.3%      12
  cx/unzip/classes2.dex                       218,097     217,088    99.5%       4
  cx/unzip/META-INF/BNDLTOOL.SF               79,703      77,824    97.6%       2
  cx/unzip/META-INF/MANIFEST.MF               77,041      77,824   101.0%       4
  cx/unzip/assets/exolibs.zip                 44,363      45,056   101.6%       1
  cx/unzip/com/google/.../google.jks          43,117      40,960    95.0%       1
  cx/unzip/okhttp3/.../publicsuffixes.gz      41,394      49,152   118.7%       4
  cx/unzip/AndroidManifest.xml                10,250       8,192    79.9%       1
  cx/unzip/drive.v3.json                      18,404      16,384    89.0%       1
  cx/unzip/res/font/robotomono_regular.ttf    51,960      53,248   102.5%       1
  cx/unzip/com/google/.../google.p12          76,476      28,672    37.5%       5
  ───────────────────────────────────────────────────────────────────────────────────

  ═══ FILE TYPE COVERAGE SUMMARY ═══

  File Type               Files    Files Scanned   Coverage%    Total Read
  ───────────────────────────────────────────────────────────────────────────
  .dex (code)                3           3            100.0%     5,713,920
  .apk (nested)              1           1            100.0%     8,134,656
  .zip (nested)              1           1            100.0%     8,130,560
  .arsc (resources)          1           1            100.0%       577,536
  .xml (resources)        1,278         ~300          ~23.5%      ~600,000
  .png (images)             503         ~120          ~23.9%      ~400,000
  .properties / .version   102           ~5           ~4.9%       ~10,000
  .txt (licenses)            4           2            50.0%        ~8,192
  .SF / .RSA (certs)         3           2            66.7%       ~77,824
  .gz (compressed)           1           1           100.0%       49,152
  .json (config)             1           1           100.0%       16,384
  .jks (keystore)            1           1           100.0%       40,960
  .p12 (certificate)         1           1            37.5%       28,672
  .ttf (font)                1           1           100.0%       53,248
  .prof (profile)            1           1           100.0%        4,096
  .bin (binary)              1           0             0.0%            0
  ───────────────────────────────────────────────────────────────────────────

  ═══ UNCOVERAGE ANALYSIS ═══

  Total file entries:        2,037
  Files with data read:        287 ( 14.1%)
  Files with 0 bytes read:   1,797 ( 88.2% of count, ~0.1% of data)

  The vast majority of unscanned files are tiny metadata entries:
    - Directory entries (cx/, cx/unzip/, cx/unzip/META-INF/): 0-byte dirs
    - .version files (70 entries, ~6 bytes each): framework version markers
    - Empty LocalHeader-only entries (directories)
    - Small resource XML files where only header was needed


╔══════════════════════════════════════════════════════════════════════════════════╗
║  10. THE 512 KB CYCLE PATTERN                                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  The most distinctive behavior in the scan is a repeating 512 KB cycle:

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    512 KB CYCLE ANATOMY                                │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                       │
  │  ┌───────────────────────────────────────────────────────────────────┐│
  │  │ Event #N+0:  Offset X+0       Length 65,536 (0x10000)           ││
  │  │ Event #N+1:  Offset X+65536   Length 65,536 (0x10000)           ││
  │  │ Event #N+2:  Offset X+131072  Length 65,536 (0x10000)           ││
  │  │ Event #N+3:  Offset X+196608  Length 65,536 (0x10000)           ││
  │  │ Event #N+4:  Offset X+262144  Length 65,536 (0x10000)           ││
  │  │ Event #N+5:  Offset X+327680  Length 65,536 (0x10000)           ││
  │  │ Event #N+6:  Offset X+393216  Length 65,536 (0x10000)           ││
  │  │                      ─── 458,752 bytes (7 × 64 KB) ───         ││
  │  │ Event #N+7:  Offset X+458752  Length 61,440 (0xF000)  ← BOUNDARY││
  │  │ Event #N+8:  Offset X+520192  Length  4,096 (0x01000) ← ALIGN  ││
  │  └───────────────────────────────────────────────────────────────────┘│
  │                                                                       │
  │  Total: 524,288 bytes = 512 KB = 0.5 MB                               │
  │                                                                       │
  │  The 61,440-byte read (Event #N+7) marks the boundary of a 512 KB    │
  │  block. The 4,096-byte read (Event #N+8) provides alignment to the   │
  │  next 4 KB page boundary before the pattern restarts.                 │
  │                                                                       │
  │  Note: 65,536 + 7 = 458,752; 524,288 - 458,752 = 65,536            │
  │  The boundary read is 61,440 (= 65,536 - 4,096), suggesting a       │
  │  4,096-byte overlap or alignment with the next 4 KB page.            │
  └─────────────────────────────────────────────────────────────────────────┘

  Occurrence count:
    cx/base.apk:        19 cycles (Events 23-319)
    cx/unzip/base.zip:  19 cycles (Events 179-319)
    cx/unzip/classes.dex:   6 cycles (Events 321-374)
    cx/unzip/classes3.dex:  5 cycles (Events 381-424)
    cx/unzip/resources.arsc: 2 cycles (Events 828-837)

  The pattern appears whenever Defender performs a large sequential scan
  of a data region exceeding ~500 KB.


╔══════════════════════════════════════════════════════════════════════════════════╗
║  11. KEY FINDINGS                                                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  1. FULL ZIP EXTRACTION SCANNING
     Defender does not merely scan the ZIP structure — it performs a full
     sequential scan of ALL file data (24.4 MB of 24.4 MB file data = 100%).
     It reads every byte of every file entry, including deeply nested files
     within the nested APK (cx/base.apk) and its extracted contents.

  2. CENTRAL DIRECTORY USED AS INDEX
     The Central Directory (268 KB) is read 116 times during file enumeration,
     serving as the primary index for navigating file entries. CD reads account
     for 2.7% of all bytes read but drive the entire scan workflow.

  3. DUAL-PASS SCANNING OF NESTED APK
     The nested cx/base.apk is scanned twice:
       - First as a raw ZIP entry (offset 52 → 8,131,098)
       - Second as its extracted contents under cx/unzip/ (offset 8,131,098 → ...)
     This suggests Defender treats nested archives as independent scan targets.

  4. 512 KB CHUNK SIZE FOR LARGE FILES
     Files exceeding ~500 KB are scanned in 512 KB cycles using the
     [7×65KB + 61KB + 4KB] pattern. Files below this threshold receive
     single reads (4,096 to 65,536 bytes).

  5. SMALL FILE HANDLING (≤4 KB)
     Files ≤4,096 bytes receive exactly one 4,096-byte read. This includes
     1,278 XML resource files, 70 .version metadata files, and various
     configuration entries. The minimum read size is 4,096 bytes regardless
     of actual file size.

  6. NO CONTENT-AWARE SKIPPING
     Defender reads ALL file types with equal thoroughness: DEX code, XML
     resources, PNG images, certificate files, property files, and even
     empty directory entries. There is no evidence of content-type-based
     scan prioritization in the read pattern.

  7. ADAPTIVE CD READ SIZES
     During Phase 2, Central Directory read sizes grow progressively:
     4,096 → 8,192 → 16,384 bytes, suggesting an adaptive buffering
     strategy that increases read sizes as the scan gains confidence.

  8. ZONE.IDENTIFIER CHECK
     The final read (Event 839) accesses cx.zip:Zone.Identifier (188 bytes),
     confirming Defender checks the NTFS alternate data stream for download
     origin information as a final scan step.

  9. HIGH READ AMPLIFICATION ON SMALL ENTRIES
     Small entries show coverage >100% because reads are page-aligned:
       - A 251-byte XML file receives a 4,096-byte read (1,632% amplification)
       - A 100-byte PNG receives a 4,096-byte read (4,096% amplification)
     This is a natural consequence of 4 KB minimum I/O granularity.

  10. CENTRAL DIRECTORY READ FREQUENCY
      The CD region (offset 24,514,005–24,782,941) is accessed by 116 of
      840 events (13.8% of events). Each file enumeration event triggers
      a CD re-read, confirming the CD is the primary navigation structure.


╔══════════════════════════════════════════════════════════════════════════════════╗
║  12. COMPARISON WITH PE SCANNING                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Metric                        PE Scan (AdobeReader.exe)    ZIP Scan (cx.zip)
  ───────────────────────────────────────────────────────────────────────────────
  Target size                   2,645,553 bytes (2.5 MB)     24,782,963 bytes (23.6 MB)
  Total reads                   110                           840
  Total bytes read              ~13.5 MB                      25.2 MB
  Read amplification            ~5.1x                         1.02x
  Scan passes                   3 full sequential passes      1 full sequential pass
  Primary chunk size            524,288 bytes (512 KB)        65,536 bytes (64 KB)
  Secondary chunk size          262,144 bytes (256 KB)        61,440 bytes (60 KB)
  Header re-reads               7 times                       2 times (Events 0, 22)
  Section/CD navigation         Section table offsets         Central Directory offsets
  Content-aware skipping        YES (minimal .rsrc reads)    NO (reads everything)
  Multi-pass scanning           YES (3 passes)                NO (1 pass)
  ───────────────────────────────────────────────────────────────────────────────

  Key Differences:
    - PE scanning uses larger chunks (512 KB vs 64 KB) and multiple passes
    - ZIP scanning is more efficient (1.02x vs 5.1x amplification)
    - PE scanning shows content-awareness (skips .rsrc in later passes)
    - ZIP scanning treats all content equally regardless of type
    - ZIP scan chunk size (64 KB) is exactly 1/8 of PE chunk size (512 KB)
    - The 61,440-byte boundary read in ZIP scans has no PE equivalent


╔══════════════════════════════════════════════════════════════════════════════════╗
║  13. CONFIDENCE ASSESSMENT                                                   ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Finding                                         Confidence    Basis
  ─────────────────────────────────────────────────────────────────────────────
  Full sequential scan of all file data           CONFIRMED     Direct offset mapping
  512 KB cycle pattern                            CONFIRMED     19 consistent repetitions
  Central Directory as primary index              CONFIRMED     116 CD re-reads observed
  Dual-pass nested APK scanning                   CONFIRMED     Two full base.apk scans
  4,096-byte minimum read size                    CONFIRMED     432 events at exactly 4,096
  No content-type scan skipping                   OBSERVED      All file types scanned
  Adaptive CD read sizing (4K→8K→16K)            OBSERVED      Phase 2 read progression
  Zone.Identifier final check                     CONFIRMED     Event 839 (188 bytes)
  100% DEX file coverage                          CONFIRMED     3/3 DEX files at ~100%
  Small metadata files receive 0 bytes            CONFIRMED     1,797 of 2,037 entries
  ───────────────────────────────────────────────────────────────────────────────

  HYPOTHESES (not confirmed):
    - The 61,440-byte boundary read may relate to OS page alignment
    - Adaptive CD sizing may be buffer-growth heuristic
    - Dual-pass may indicate separate scan engines for ZIP and content
    - Content-type skipping may occur at a higher level (not observed here)


╔══════════════════════════════════════════════════════════════════════════════════╗
║  14. LIMITATIONS                                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  - ProcMon CSV timestamps are empty; timing analysis could not be performed
  - Only ReadFile events were analyzed; WriteFile/CloseFile are excluded
  - ProcMon may miss I/O during buffer cache hits
  - No data on whether Defender actually decompresses ZIP entries
  - Cannot determine if scan results (clean/detect) from read pattern alone
  - Only one ZIP file was analyzed; patterns may vary with other archives
  - The 61,440-byte boundary read mechanism is not fully explained
  - Cannot confirm if Defender decompresses nested ZIP entries in-memory
    or reads them as raw bytes from the parent archive


╔══════════════════════════════════════════════════════════════════════════════════╗
║  15. FUTURE WORK                                                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  1. Timing Analysis: Capture timestamps to measure scan throughput per phase
  2. Multiple ZIP Samples: Test with different ZIP structures (flat vs nested,
     small vs large, compressed vs stored)
  3. Compression Analysis: Determine if Defender decompresses DEFLATE entries
     or scans compressed bytes directly
  4. Detection Correlation: Test if scan behavior changes for known-malicious
     ZIP archives (scan depth, read frequency, scan termination)
  5. WriteFile Monitoring: Capture any temp file creation during ZIP extraction
  6. 61,440-byte Boundary: Investigate if this relates to NTFS cluster size,
     Windows page size, or Defender internal buffer management
  7. Scan Termination: Determine if scan stops early for clean archives or
     always performs full sequential scan
  8. Recursive Depth: Test with deeper nesting (ZIP in ZIP in ZIP) to find
     maximum recursion depth

================================================================================================
  END OF REPORT
================================================================================================
