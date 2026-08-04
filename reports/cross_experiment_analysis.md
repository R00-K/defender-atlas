# Cross-Experiment Analysis

## Reads common to every experiment

Every experiment performs a first read of `offset 0, length 4096`, and the first
seven region accesses are identical (see timeline_analysis.md).  The PE regions
touched in **all 30** experiments are:

.data, .text, DOS Header, DOS Stub, File Header, IAT Directory, Import Directory, NT Headers, Optional Header, Section Table

These are exactly the header chain plus the code/data/import regions — the minimum
set a structure-aware scanner must touch to parse and classify a PE.

## Recurring offset ranges

Aggregating reads over the normalized file position (64 bins of offset/file-size):

* Bins 0.00–0.10 (header + first sections) are read by all experiments.
* The final bin (0.98–1.00, the file footer) is read by all experiments.
* Interior bins are read by a fraction proportional to the number of large files in
  the dataset (the body of small files is covered by their single linear pass).
* Read *starts* cluster at the header, the section boundaries and the footer.

## Recurring chunk sizes

| Band | Total reads | % experiments using |
|---|---|---|
| <=512B | 12 | 13 |
| 513B-1K | 3 | 3 |
| 1-2K | 2 | 3 |
| 2-4K | 1,007 | 100 |
| 4-8K | 354 | 100 |
| 8-16K | 53 | 47 |
| 16-32K | 69 | 17 |
| 32-64K | 1,076 | 27 |
| 64-128K | 9 | 23 |
| 128-256K | 645 | 40 |
| 256-512K | 553 | 47 |
| 512K-1M | 0 | 0 |
| >1M | 0 | 0 |

Two chunk families are universal: **2–4 KiB** (metadata probing) and **4–8 KiB**
(section probing), both present in 100% of experiments.  Streaming families
(32–64 KiB, 128–256 KiB, 256–512 KiB) appear only in the large-file experiments.

## Recurring access order

For every experiment the first-access order of the header chain is identical
DOS Header → DOS Stub → NT Headers →
File Header → Optional Header → Section Table (30/30).  After
that, the next region is the sample's first section (`.text` in 27/30, `.rdata` in
the remainder).  After the header chain the order is sample-specific and follows the
binary's layout.

## Repeated scan passes

Pass counts: {"1": 1, "2": 23, "5": 6}.

* 2 passes (23/30): structured probe + one linear body sweep.
* 5 passes (6/30): structured probe + multiple body sweeps (overlay stream,
  resource sweep, per-section sweeps).
* 1 pass (1/30): a 9,216-byte file read in two reads.

## Scan stages

The rule-based phase detector found 2–6 phases per experiment (median
4).
The canonical stage sequence is:

**Header Inspection → Directory Parsing → (Resource Parsing) → (Code Scanning) →
(Overlay Inspection) → (Relocation Processing)**

Overlay Inspection appears in the 14 experiments whose files carry appended data.

## Read density

Read-start density is sparse: a mean of
37.7%
of 4 KiB blocks contain a read start, while byte coverage is 100%.  Density
(entropy) is strongly correlated with block coverage (r = 0.86).

## Scan coverage

Byte coverage = 100.0% in all 30 experiments (zero variance).  The scanner never
reads a strict subset of a file.

## Scan similarities and differences

**Similarities:** identical first read, identical header chain order, 4 KiB-aligned
starts, complete coverage, power-of-two chunk sizes, deterministic phase order.

**Differences:** number of passes (1/2/5), amplification (1.0–6.0x), use of
streaming chunk sizes, presence of an early footer probe, and whether the scan ends
with a header re-read.  Differences are almost entirely explained by file size and
by the presence of an overlay / resources.

## Automatic clustering

Experiments were clustered with agglomerative (Ward) clustering on standardized
features: normalized offset histogram (64 bins), region-class read fractions,
chunk-size fractions, amplification, sequentiality, entropy and pass count.

* Ward linkage produced 8 clusters at the silhouette-maximizing cut
  (silhouette 0.1969).
* The grouping is driven by scan shape: the four sublimeBase.exe runs cluster
  together, the unsigned Go-style binaries cluster together, and the small system
  binaries form a large low-read-count group.
* The silhouette of 0.1969 is modest — scans form a continuum (size
  gradient) rather than discrete clusters.  The dendrogram (fig_11) and PCA
  projection (fig_12) show the size gradient along PC1.

**Caution.** Clustering is exploratory; n = 30 and features are highly
collinear.  Treat cluster membership as descriptive, not as evidence of distinct
scanning engines.
