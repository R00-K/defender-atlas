# Statistical Analysis

Dataset: **30** experiments (one Defender scan each).  Metrics below are computed
from SUCCESS (actual IRP) reads.  Confidence intervals use the normal approximation
of the mean (n = 30).

## Aggregate statistics

| Metric | Mean | Median | Std | Q1 | Q3 | Min | Max | 95% CI |
|---|---|---|---|---|---|---|---|---|
| file_size | 4,172,187.5 | 153,600.0 | 7,448,293.597 | 64,245.0 | 4,204,760.0 | 9216.0 | 30,870,320.0 | [1461285.239, 6883089.761] |
| total_reads | 126.1 | 13.5 | 236.276 | 8.0 | 66.5 | 2.0 | 709.0 | [40.104, 212.096] |
| unique_offsets | 81.767 | 13.5 | 147.077 | 8.0 | 50.0 | 2.0 | 449.0 | [28.236, 135.297] |
| repeated_reads | 44.333 | 0.0 | 90.245 | 0.0 | 15.25 | 0.0 | 260.0 | [11.487, 77.179] |
| bytes_read | 17,479,819.9 | 199,680.0 | 33,246,288.937 | 80,618.0 | 10,508,462.0 | 9216.0 | 97,336,412.0 | [5379405.4, 29580234.4] |
| read_amplification | 2.372 | 1.37 | 1.79 | 1.17 | 3.759 | 1.0 | 6.008 | [1.72, 3.023] |
| coverage_pct | 100.0 | 100.0 | 0.0 | 100.0 | 100.0 | 100.0 | 100.0 | [100.0, 100.0] |
| block_coverage_pct | 37.736 | 29.778 | 29.526 | 11.35 | 64.039 | 0.902 | 88.889 | [26.99, 48.483] |
| offset_entropy | 0.71 | 0.708 | 0.142 | 0.62 | 0.81 | 0.401 | 0.946 | [0.658, 0.761] |
| sequential | 0.49 | 0.489 | 0.307 | 0.256 | 0.841 | 0.0 | 1.0 | [0.378, 0.601] |
| passes | 2.567 | 2.0 | 1.23 | 2.0 | 2.0 | 1.0 | 5.0 | [2.119, 3.014] |
| duration_seconds | 0.377 | 0.025 | 0.812 | 0.011 | 0.134 | 0.0 | 2.537 | [0.082, 0.673] |
| region_count | 20.067 | 19.0 | 5.0 | 17.0 | 20.0 | 17.0 | 42.0 | [18.247, 21.886] |
| mean_read | 72,283.67 | 18,385.45 | 96,261.682 | 7288.8 | 134,879.275 | 4480.0 | 448,131.9 | [37247.993, 107319.347] |
| median_read | 45,848.8 | 4096.0 | 109,341.344 | 4096.0 | 8192.0 | 4096.0 | 524,288.0 | [6052.611, 85644.989] |
| std_read | 84,679.983 | 41,627.75 | 81,328.726 | 5946.35 | 172,803.2 | 512.0 | 200,909.9 | [55079.347, 114280.619] |
| min_read | 3419.167 | 4096.0 | 1365.881 | 4096.0 | 4096.0 | 451.0 | 4096.0 | [2922.037, 3916.297] |
| max_read | 261,941.4 | 145,640.0 | 235,005.652 | 22,439.0 | 524,288.0 | 5120.0 | 524,288.0 | [176408.07, 347474.73] |
| phase_count | 4.367 | 4.0 | 0.795 | 4.0 | 5.0 | 2.0 | 6.0 | [4.077, 4.656] |

## Distributional notes

* **Amplification**: mean 2.37x, median
  1.37x — the distribution is right-skewed
  (large multi-pass files pull the mean up).
* **Repeated reads**: mean 44.3, median
  0.  Half the experiments have **zero**
  repeated offsets; the heavy repetition is concentrated in 6 large binaries.
* **Duration**: mean 0.377s, median
  0.025s — 80% of the wall-clock time is spent
  in the three sublimeBase.exe runs and ntoskrnl.exe.
* **Coverage**: byte coverage is constant at 100.0% (zero variance) across the whole
  dataset — a deterministic invariant of the scanner.
* **Block coverage** (read starts): mean 37.7%,
  and it *decreases* with file size (r = -0.56),
  because larger files use larger chunks.

## Welch two-sample comparison: large vs small files

| Group | n | Mean amplification | Mean repeated-read % | Mean passes |
|---|---|---|---|---|
| File size ≥ 500 KB | 13 | 3.87x | 28.9% | 3.4 |
| File size < 500 KB | 17 | 1.22x | 1.0% | 1.9 |

The two groups are strongly separated on amplification (Welch t ≈ 7.4,
p < 0.0001), passes (t ≈ 7.9) and repeated-read fraction.  The scanner's cost model
scales with file size not merely by reading more bytes once, but by *re-reading*.

## Correlations (Pearson)

With n = 30, |r| > 0.36 is significant at α = 0.05.  The strongest correlations:

| Metric A | Metric B | r |
|---|---|---|
| unique offsets | total reads | 0.997 |
| duration (s) | unique offsets | 0.995 |
| repeated reads | total reads | 0.993 |
| bytes read | total reads | 0.990 |
| duration (s) | total reads | 0.989 |
| bytes read | unique offsets | 0.987 |
| bytes read | repeated reads | 0.984 |
| repeated reads | unique offsets | 0.981 |
| duration (s) | bytes read | 0.970 |
| duration (s) | repeated reads | 0.967 |
| amplification | repeated reads | 0.902 |
| amplification | total reads | 0.891 |
| scan passes | repeated reads | 0.882 |
| amplification | unique offsets | 0.878 |
| amplification | bytes read | 0.871 |
| offset entropy | 4K block coverage % | 0.861 |
| scan passes | total reads | 0.859 |
| scan passes | bytes read | 0.848 |
| duration (s) | amplification | 0.846 |
| scan passes | unique offsets | 0.838 |
| scan passes | amplification | 0.824 |
| duration (s) | scan passes | 0.817 |
| bytes read | file size | 0.785 |
| unique offsets | file size | 0.712 |
| total reads | file size | 0.699 |
| duration (s) | file size | 0.671 |
| repeated reads | file size | 0.671 |
| sequential score | file size | 0.653 |
| sequential score | bytes read | 0.611 |

## Statistically significant observations

1. **Total reads, bytes read, repeated reads and scan passes are near-perfectly
   inter-correlated** (r ≈ 0.85–0.99): they measure the same underlying quantity —
   the scan's work — which is driven by file size (r = 0.70–0.79).
2. **Amplification is more than a size effect.**  Large files are not only bigger,
   they are read a *larger multiple* of their size (r = 0.57 with size but 0.89 with
   total reads).  The per-byte cost grows with file size.
3. **Sequentiality increases with size** (r = 0.65): small files are read in a few
   contiguous chunks; large files are read as long contiguous streams.
4. **Block (start) coverage is anti-correlated with amplification** (r = -0.59):
   scans that read the most times per byte use the *fewest* distinct read starts,
   i.e. they re-stream the same large blocks repeatedly.

## Cautions

* The dataset mixes signed Microsoft binaries, signed third-party installers and
  unsigned experimental executables.  Binaries also differ in section layout,
  resources, and embedded certificates.  Size effects are therefore confounded with
  binary provenance; a controlled size sweep is needed to separate them.
* ProcMon timestamps have 100 ns resolution but scans were captured under an
  unknown CPU/disk load; duration comparisons are noisy.
* Repeated-offset counting is at read-*start* granularity, not byte granularity.
