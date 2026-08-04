"""Publication-quality figure generation for the Defender scan research.

Writes to reports/figures/ (primary), reports/heatmaps/ and
reports/charts/.  Consumes pipeline_results.json and cross_analysis.json.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import cm
from matplotlib.ticker import FuncFormatter, LogLocator

from pipeline import CHUNK_BANDS, OUT_DIR, load

FIG_DIR = OUT_DIR / "figures"
HEAT_DIR = OUT_DIR / "heatmaps"
CHART_DIR = OUT_DIR / "charts"

plt.rcParams.update(
    {
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "figure.dpi": 130,
        "savefig.bbox": "tight",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "font.family": "DejaVu Sans",
    }
)

PALETTE = plt.cm.tab20


def _save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path.name}")


def _kb(x, pos=None):
    return f"{int(x):,}"


def _human(x, pos=None):
    if x >= 1e6:
        return f"{x/1e6:.1f}M"
    if x >= 1e3:
        return f"{x/1e3:.0f}K"
    return f"{int(x)}"


def _read_count_by_offset(res) -> Counter[int]:
    c: Counter[int] = Counter()
    for e in res.reads:
        c[e["offset"]] += 1
    return c


# ── figures 1-5: aggregate charts ──────────────────────────────────────


def fig_amplification(results) -> None:
    exps = [f"{r.exp_id:02d}" for r in results]
    vals = [r.read_amplification for r in results]
    colors = ["#c0392b" if v > 3 else ("#e67e22" if v > 1.5 else "#2ecc71") for v in vals]
    fig, ax = plt.subplots(figsize=(11, 4))
    ax.bar(exps, vals, color=colors)
    ax.axhline(np.mean(vals), color="#2c3e50", ls="--", lw=1, label=f"mean {np.mean(vals):.2f}x")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Read amplification (bytes read / file size)")
    ax.set_title("Read amplification per experiment (SUCCESS reads only)")
    ax.legend()
    _save(fig, FIG_DIR / "fig_01_read_amplification.png")
    _save(fig, CHART_DIR / "amplification_bar.png")


def fig_duration_vs_size(results) -> None:
    sizes = [r.file_size for r in results]
    durs = [r.duration_seconds for r in results]
    exps = [str(r.exp_id) for r in results]
    fig, ax = plt.subplots(figsize=(8, 5))
    sc = ax.scatter(sizes, durs, c=np.log10(sizes), cmap="viridis", s=60, edgecolor="k", lw=0.4)
    for s, d, e in zip(sizes, durs, exps):
        ax.annotate(e, (s, d), textcoords="offset points", xytext=(4, 4), fontsize=7)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("File size (bytes)")
    ax.set_ylabel("Scan duration (s)")
    ax.set_title("Scan duration vs file size (log-log)")
    fig.colorbar(sc, ax=ax, label="log10 size")
    _save(fig, FIG_DIR / "fig_02_duration_vs_size.png")
    _save(fig, CHART_DIR / "duration_scatter.png")


def fig_read_length_hist(results) -> None:
    all_len = [e["length"] for r in results for e in r.reads]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.hist(all_len, bins=40, color="#3498db", edgecolor="white", log=True)
    ax.set_xlabel("Read length (bytes)")
    ax.set_ylabel("Reads (log scale)")
    ax.set_title("Read-length histogram across all experiments")
    ax.xaxis.set_major_formatter(FuncFormatter(_human))
    _save(fig, FIG_DIR / "fig_03_read_length_histogram.png")
    _save(fig, CHART_DIR / "read_length_histogram.png")


def fig_chunk_distribution(results) -> None:
    names = [name for _, _, name in CHUNK_BANDS]
    totals = {name: 0 for _, _, name in CHUNK_BANDS}
    for r in results:
        for _, _, name in CHUNK_BANDS:
            totals[name] += r.chunk_dist.get(name, 0)
    vals = [totals[n] for n in names]
    fig, ax = plt.subplots(figsize=(9, 4))
    bars = ax.bar(names, vals, color="#16a085")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,}", ha="center", va="bottom", fontsize=8)
    ax.set_yscale("log")
    ax.set_xlabel("Chunk-size band")
    ax.set_ylabel("Reads (log)")
    ax.set_title("Aggregate chunk-size distribution")
    ax.tick_params(axis="x", rotation=35)
    _save(fig, FIG_DIR / "fig_04_chunk_size_distribution.png")
    _save(fig, CHART_DIR / "chunk_size_distribution.png")


def fig_offset_density(results) -> None:
    """Aggregate normalized offset histogram across experiments."""
    nbins = 64
    hist = np.zeros(nbins)
    for r in results:
        for e in r.reads:
            b = min(int((e["offset"] / r.file_size) * nbins), nbins - 1)
            hist[b] += 1
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(np.arange(nbins), hist, width=1.0, color="#8e44ad")
    ax.set_xlabel("Normalized file position (offset / file size)")
    ax.set_ylabel("Reads")
    ax.set_title("Aggregate read density across the normalized file")
    ax.set_xticks(np.arange(0, nbins + 1, 8))
    ax.set_xticklabels([f"{i/nbins:.2f}" for i in range(0, nbins + 1, 8)])
    _save(fig, FIG_DIR / "fig_05_offset_density.png")
    _save(fig, CHART_DIR / "offset_histogram.png")


def fig_read_frequency_by_offset(results) -> None:
    """How many times each unique offset is read (scatter)."""
    all_off: Counter[int] = Counter()
    for r in results:
        for e in r.reads:
            all_off[e["offset"]] += 1
    offs = sorted(all_off)
    counts = [all_off[o] for o in offs]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.scatter(offs, counts, s=8, alpha=0.5, color="#2980b9")
    ax.set_xlabel("Offset (bytes)")
    ax.set_ylabel("Number of reads")
    ax.set_title("Read frequency per unique offset (all experiments)")
    ax.xaxis.set_major_formatter(FuncFormatter(_human))
    ax.set_yscale("log")
    _save(fig, FIG_DIR / "fig_06_read_frequency_by_offset.png")
    _save(fig, CHART_DIR / "read_frequency_offsets.png")


# ── figures 7-8: region charts ─────────────────────────────────────────


def fig_region_frequency(region_freq) -> None:
    names = [r["region"] for r in region_freq]
    pct = [r["pct_experiments"] for r in region_freq]
    fig, ax = plt.subplots(figsize=(9, 6))
    colors = ["#e74c3c" if p == 100 else "#f39c12" for p in pct]
    ax.barh(names, pct, color=colors)
    ax.axvline(100, color="#2c3e50", ls="--", lw=0.8)
    ax.set_xlabel("Experiments accessing region (%)")
    ax.set_title("PE region access frequency across experiments")
    ax.set_xlim(0, 105)
    ax.invert_yaxis()
    _save(fig, FIG_DIR / "fig_07_region_frequency.png")
    _save(fig, CHART_DIR / "region_frequency.png")


def fig_region_bytes(region_aggregate) -> None:
    top = region_aggregate[:15]
    names = [r["region"] for r in top]
    bytes_ = [r["total_bytes"] for r in top]
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(names, bytes_, color="#27ae60")
    ax.set_xlabel("Total bytes read (log)")
    ax.set_title("Total bytes read per PE region")
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(_human))
    ax.invert_yaxis()
    _save(fig, FIG_DIR / "fig_08_region_bytes.png")
    _save(fig, CHART_DIR / "region_bytes.png")


# ── figures 9-12: correlation / similarity / clustering ───────────────


def fig_correlation(corr) -> None:
    M = np.array(corr["matrix"])
    labels = corr["metrics"]
    fig, ax = plt.subplots(figsize=(9.5, 8.5))
    im = ax.imshow(M, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=60, ha="right", fontsize=8)
    ax.set_yticks(range(len(labels)), labels, fontsize=8)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if abs(M[i, j]) > 0.6:
                ax.text(j, i, f"{M[i,j]:.2f}", ha="center", va="center", fontsize=6,
                        color="white" if abs(M[i, j]) > 0.7 else "black")
    fig.colorbar(im, ax=ax, label="Pearson r", shrink=0.8)
    ax.set_title("Correlation matrix of scan metrics")
    _save(fig, FIG_DIR / "fig_09_correlation_matrix.png")
    _save(fig, HEAT_DIR / "correlation_matrix.png")


def fig_similarity(cluster_res, results) -> None:
    D = np.array(cluster_res["distances"])
    names = cluster_res["names"]
    fig, ax = plt.subplots(figsize=(8.5, 7.5))
    im = ax.imshow(D, cmap="magma")
    ax.set_xticks(range(len(names)), names, rotation=90, fontsize=7)
    ax.set_yticks(range(len(names)), names, fontsize=7)
    fig.colorbar(im, ax=ax, label="Euclidean distance (standardized features)", shrink=0.8)
    ax.set_title("Experiment similarity (pairwise distance)")
    _save(fig, FIG_DIR / "fig_10_similarity_matrix.png")
    _save(fig, HEAT_DIR / "similarity_matrix.png")


def fig_dendrogram(cluster_res) -> None:
    Z = np.array(cluster_res["Z"])
    fig, ax = plt.subplots(figsize=(9, 5))
    from scipy.cluster.hierarchy import dendrogram

    dendrogram(Z, labels=cluster_res["names"], ax=ax, leaf_rotation=90, leaf_font_size=8)
    ax.set_ylabel("Ward linkage distance")
    ax.set_title(f"Agglomerative clustering of experiments (k={cluster_res['k']}, "
                 f"silhouette={cluster_res['silhouette']})")
    _save(fig, FIG_DIR / "fig_11_dendrogram.png")
    _save(fig, CHART_DIR / "dendrogram.png")


def fig_cluster_pca(cluster_res, results) -> None:
    from sklearn.decomposition import PCA

    X = np.array(json.loads(json.dumps(cluster_res["feature_labels"], default=str)) and _feature_matrix(results))
    Z = X.copy()
    Z = (Z - Z.mean(axis=0)) / (Z.std(axis=0) + 1e-9)
    pca = PCA(n_components=2).fit_transform(Z)
    labels = cluster_res["labels"]
    k = cluster_res["k"]
    fig, ax = plt.subplots(figsize=(8, 6))
    for cl in sorted(set(labels)):
        m = np.array([l == cl for l in labels])
        ax.scatter(pca[m, 0], pca[m, 1], label=f"cluster {cl}", s=70, alpha=0.85,
                   color=PALETTE(cl % 20), edgecolor="k", lw=0.5)
    for i, name in enumerate(cluster_res["names"]):
        ax.annotate(name[-2:], (pca[i, 0], pca[i, 1]), fontsize=7,
                    textcoords="offset points", xytext=(4, 4))
    ax.set_xlabel("PC1")
    ax.set_ylabel("PC2")
    ax.set_title(f"Experiments projected on first 2 PCs, colored by cluster (k={k})")
    ax.legend(fontsize=8)
    _save(fig, FIG_DIR / "fig_12_cluster_pca.png")
    _save(fig, CHART_DIR / "cluster_pca.png")


def _feature_matrix(results):
    from cross_analysis import combined_feature_matrix

    X, _ = combined_feature_matrix(results)
    return X


# ── figures 13-18: timelines and heatmaps ─────────────────────────────


def fig_access_timelines(results) -> None:
    """Offset vs event index for every experiment (grid of ladders)."""
    n = len(results)
    cols, rows = 6, 5
    fig, axes = plt.subplots(rows, cols, figsize=(16, 12))
    for ax, r in zip(axes.flat, results):
        offs = [e["offset"] / r.file_size for e in r.reads]
        ax.plot(range(len(offs)), offs, lw=0.6, color="#34495e")
        ax.set_title(f"{r.exp_id:02d} {r.sample[:16]}", fontsize=7)
        ax.set_ylim(0, 1.05)
        ax.set_yticks([0, 0.5, 1.0])
        ax.set_yticklabels(["0", ".5", "1"], fontsize=6)
        ax.tick_params(axis="x", labelbottom=False)
        ax.set_xlim(0)
    fig.suptitle("Normalized read offset vs read sequence index per experiment", y=0.99)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    _save(fig, FIG_DIR / "fig_13_access_timelines.png")


def fig_region_timeline(results) -> None:
    """For selected experiments: offset vs order colored by region class."""
    picks = [0, 1, 2, 6, 14, 25]
    fig, axes = plt.subplots(2, 3, figsize=(15, 7.5))
    class_colors = {
        "headers": "#e74c3c", "directories": "#e67e22", "code": "#2ecc71",
        "readonly": "#3498db", "data": "#9b59b6", "resources": "#f1c40f",
        "overlay": "#95a5a6", "section": "#1abc9c", "relocations": "#d35400",
        "exceptions": "#c0392b", "tls": "#16a085",
    }
    for ax, i in zip(axes.flat, picks):
        r = results[i]
        rmap = r.regions
        for e in r.reads:
            # find region class at this offset
            cls = None
            for name, ri in rmap.items():
                if ri.start <= e["offset"] <= ri.end:
                    cls = ri.rclass
                    break
            ax.scatter(e["offset"], e["i"] if False else e["offset"] / r.file_size,
                       color=class_colors.get(cls, "#cccccc"), s=6)
        ax.set_title(f"{r.exp_id:02d} {r.sample[:18]}", fontsize=8)
        ax.set_yticks([])
    fig.suptitle("Read offsets colored by PE region class (normalized position)")
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    _save(fig, FIG_DIR / "fig_14_region_timeline.png")


def fig_offset_density_heatmap(results) -> None:
    """Heatmap: experiments x normalized offset bins (read counts)."""
    nbins = 64
    M = np.zeros((len(results), nbins))
    for i, r in enumerate(results):
        for e in r.reads:
            b = min(int((e["offset"] / r.file_size) * nbins), nbins - 1)
            M[i, b] += 1
    M = np.log1p(M)
    fig, ax = plt.subplots(figsize=(12, 7))
    im = ax.imshow(M, aspect="auto", cmap="inferno", interpolation="nearest")
    ax.set_yticks(range(len(results)), [f"{r.exp_id:02d}" for r in results], fontsize=7)
    ax.set_xticks(np.arange(0, nbins + 1, 8))
    ax.set_xticklabels([f"{i/nbins:.2f}" for i in range(0, nbins + 1, 8)])
    ax.set_xlabel("Normalized file position")
    ax.set_ylabel("Experiment")
    fig.colorbar(im, ax=ax, label="log1p(read count)", shrink=0.8)
    ax.set_title("Read-density heatmap (normalized position x experiment)")
    _save(fig, FIG_DIR / "fig_15_offset_density_heatmap.png")
    _save(fig, HEAT_DIR / "offset_density_heatmap.png")


def fig_coverage_heatmap(region_aggregate, results) -> None:
    """Region x experiment coverage-percent heatmap."""
    regions = [r["region"] for r in region_aggregate if r["pct_experiments"] >= 30]
    M = np.full((len(regions), len(results)), np.nan)
    for j, r in enumerate(results):
        for i, name in enumerate(regions):
            ri = r.regions.get(name)
            if ri is not None:
                M[i, j] = ri.coverage_pct
    fig, ax = plt.subplots(figsize=(13, 9))
    im = ax.imshow(M, aspect="auto", cmap="viridis", vmin=0, vmax=100)
    ax.set_yticks(range(len(regions)), regions, fontsize=7)
    ax.set_xticks(range(len(results)), [f"{r.exp_id:02d}" for r in results], rotation=90, fontsize=7)
    fig.colorbar(im, ax=ax, label="coverage %", shrink=0.8)
    ax.set_title("Per-region read coverage (%) across experiments")
    _save(fig, FIG_DIR / "fig_16_coverage_heatmap.png")
    _save(fig, HEAT_DIR / "region_coverage_heatmap.png")


def fig_region_reads_heatmap(region_aggregate, results) -> None:
    """Region x experiment read-count heatmap (log scaled)."""
    regions = [r["region"] for r in region_aggregate if r["pct_experiments"] >= 30]
    M = np.full((len(regions), len(results)), 0.0)
    for j, r in enumerate(results):
        for i, name in enumerate(regions):
            ri = r.regions.get(name)
            if ri is not None:
                M[i, j] = ri.reads
    M = np.log1p(M)
    fig, ax = plt.subplots(figsize=(13, 9))
    im = ax.imshow(M, aspect="auto", cmap="plasma")
    ax.set_yticks(range(len(regions)), regions, fontsize=7)
    ax.set_xticks(range(len(results)), [f"{r.exp_id:02d}" for r in results], rotation=90, fontsize=7)
    fig.colorbar(im, ax=ax, label="log1p(read count)", shrink=0.8)
    ax.set_title("Per-region read counts across experiments")
    _save(fig, FIG_DIR / "fig_17_region_reads_heatmap.png")
    _save(fig, HEAT_DIR / "region_reads_heatmap.png")


def fig_pass_structure(results) -> None:
    """Offset vs event index with passes highlighted for selected exps."""
    picks = [0, 1, 2, 6, 14]
    fig, axes = plt.subplots(1, 5, figsize=(18, 4))
    for ax, i in zip(axes, picks):
        r = results[i]
        offs = [e["offset"] / r.file_size for e in r.reads]
        pass_no = np.zeros(len(offs), dtype=int)
        # reconstruct pass per read using running max
        running = -1
        p = 0
        for k, o in enumerate(offs):
            if o < running:
                p += 1
            running = max(running, o)
            pass_no[k] = p
        colors = [PALETTE(p % 20) for p in pass_no]
        ax.scatter(range(len(offs)), offs, c=colors, s=10)
        ax.set_title(f"{r.exp_id:02d} {r.sample[:14]} ({r.passes} passes)", fontsize=8)
        ax.set_yticks([0, 0.5, 1.0])
        ax.set_yticklabels(["0", ".5", "1"], fontsize=7)
        ax.set_ylim(0, 1.05)
    fig.suptitle("Detected forward scan passes (color = pass number)")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    _save(fig, FIG_DIR / "fig_18_pass_structure.png")


def fig_read_size_distribution(results) -> None:
    """Violin of read sizes per experiment."""
    data = [[e["length"] for e in r.reads] for r in results]
    fig, ax = plt.subplots(figsize=(14, 5))
    parts = ax.violinplot(data, positions=range(len(results)), showmedians=True, widths=0.9)
    for pc in parts["bodies"]:
        pc.set_facecolor("#5dade2")
        pc.set_alpha(0.6)
    ax.set_xticks(range(len(results)), [f"{r.exp_id:02d}" for r in results], fontsize=7)
    ax.set_yscale("log")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Read length (bytes, log)")
    ax.set_title("Read-size distribution per experiment")
    _save(fig, FIG_DIR / "fig_19_read_size_distribution.png")


def fig_repeated_offsets(results) -> None:
    """Repeated reads on the header region: offset vs times read."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    for ax, i in zip(axes, [0, 1, 2]):
        r = results[i]
        counts = _read_count_by_offset(r)
        header_offs = sorted(o for o in counts if o < 4096 or (o < 20000 and o in counts))
        ax.bar([str(o) for o in header_offs], [counts[o] for o in header_offs], color="#8e44ad")
        ax.set_title(f"{r.exp_id:02d} {r.sample[:16]}", fontsize=8)
        ax.set_xlabel("Offset (bytes)")
        ax.set_ylabel("Reads")
        ax.tick_params(axis="x", rotation=90, labelsize=6)
    fig.suptitle("Repeated reads near the PE header region")
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    _save(fig, FIG_DIR / "fig_20_header_repeated_reads.png")


def fig_pass_hist(results) -> None:
    c = Counter(r.passes for r in results)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar([str(k) for k in sorted(c)], [c[k] for k in sorted(c)], color="#16a085")
    ax.set_xlabel("Number of forward scan passes")
    ax.set_ylabel("Experiments")
    ax.set_title("Distribution of scan passes")
    for i, k in enumerate(sorted(c)):
        ax.text(i, c[k] + 0.1, str(c[k]), ha="center", fontsize=9)
    _save(fig, FIG_DIR / "fig_21_passes_histogram.png")
    _save(fig, CHART_DIR / "passes_distribution.png")


def fig_phase_counts(results) -> None:
    c = Counter(p for r in results for p in r.phase_names)
    names = [n for n, _ in c.most_common()]
    vals = [c[n] for n in names]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, vals, color="#2980b9")
    ax.set_xlabel("Detected phase")
    ax.set_ylabel("Experiments")
    ax.set_title("Phase detection frequency")
    ax.tick_params(axis="x", rotation=25)
    _save(fig, FIG_DIR / "fig_22_phase_counts.png")


def run() -> None:
    results = load(OUT_DIR / "pipeline_results.json")
    cross = json.loads((OUT_DIR / "cross_analysis.json").read_text(encoding="utf-8"))
    for d in (FIG_DIR, HEAT_DIR, CHART_DIR):
        d.mkdir(parents=True, exist_ok=True)

    fig_amplification(results)
    fig_duration_vs_size(results)
    fig_read_length_hist(results)
    fig_chunk_distribution(results)
    fig_offset_density(results)
    fig_read_frequency_by_offset(results)
    fig_region_frequency(cross["region_frequency"])
    fig_region_bytes(cross["region_aggregate"])
    fig_correlation(cross["correlation"])
    fig_similarity(cross["clustering"], results)
    fig_dendrogram(cross["clustering"])
    fig_cluster_pca(cross["clustering"], results)
    fig_access_timelines(results)
    fig_region_timeline(results)
    fig_offset_density_heatmap(results)
    fig_coverage_heatmap(cross["region_aggregate"], results)
    fig_region_reads_heatmap(cross["region_aggregate"], results)
    fig_pass_structure(results)
    fig_read_size_distribution(results)
    fig_repeated_offsets(results)
    fig_pass_hist(results)
    fig_phase_counts(results)
    print("all figures written")


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    run()
