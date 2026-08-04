"""Cross-experiment analysis: similarity, clustering, common patterns,
statistical research, and anomaly detection over the parsed experiments.

Consumes the JSON produced by :mod:`pipeline` and produces structured
results consumed by the figure/report writers.
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from scipy import cluster, stats as sp_stats
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, pairwise_distances
from sklearn.preprocessing import StandardScaler

from pipeline import (
    CHUNK_BANDS,
    REGION_CLASSES,
    OUT_DIR,
    chunk_band,
    load,
)

BLOCK = 4096
NBINS = 64


# ── feature vectors ─────────────────────────────────────────────────────


def normalized_offset_histogram(res) -> np.ndarray:
    """Normalized histogram of read offsets in 64 bins over [0,1]."""
    h = np.zeros(NBINS)
    for e in res.reads:
        frac = e["offset"] / res.file_size if res.file_size else 0.0
        b = min(int(frac * NBINS), NBINS - 1)
        h[b] += 1
    tot = h.sum()
    if tot > 0:
        h /= tot
    return h


def region_class_vector(res) -> np.ndarray:
    """Fraction of reads in each semantic region class."""
    v = np.zeros(len(REGION_CLASSES))
    total = sum(res.region_classes.get(c, {}).get("reads", 0) for c in REGION_CLASSES)
    if total:
        for i, c in enumerate(REGION_CLASSES):
            v[i] = res.region_classes.get(c, {}).get("reads", 0) / total
    return v


def chunk_vector(res) -> np.ndarray:
    """Fraction of reads in each chunk-size band."""
    v = np.zeros(len(CHUNK_BANDS))
    total = res.total_reads
    if total:
        for i, (lo, hi, name) in enumerate(CHUNK_BANDS):
            v[i] = res.chunk_dist.get(name, 0) / total
    return v


def combined_feature_matrix(results) -> tuple[np.ndarray, list[str]]:
    """Stack normalized features into a matrix (experiments x features)."""
    rows = []
    names = []
    for r in results:
        f = np.concatenate(
            [
                normalized_offset_histogram(r),
                region_class_vector(r),
                chunk_vector(r),
                np.array(
                    [
                        r.read_amplification,
                        r.sequential,
                        r.offset_entropy,
                        min(r.passes, 8) / 8.0,
                    ]
                ),
            ]
        )
        rows.append(f)
        names.append(f"{r.exp_id:06d}")
    return np.vstack(rows), names


def feature_labels() -> list[str]:
    return (
        [f"bin{i}" for i in range(NBINS)]
        + [f"cls:{c}" for c in REGION_CLASSES]
        + [name for _, _, name in CHUNK_BANDS]
        + ["amp", "sequential", "entropy", "passes"]
    )


# ── clustering ──────────────────────────────────────────────────────────


def cluster_experiments(results) -> dict[str, Any]:
    X, names = combined_feature_matrix(results)
    Z = StandardScaler().fit_transform(X)

    # agglomerative clustering, ward linkage
    linkage = cluster.hierarchy.linkage(Z, method="ward")
    # choose cluster count by silhouette on kmeans + ward flat clusters
    best: dict[str, Any] = {"k": 1, "silhouette": -1.0, "labels": None}
    max_k = min(8, len(results) - 1)
    for k in range(2, max_k + 1):
        labs = cluster.hierarchy.fcluster(linkage, k, criterion="maxclust")
        if len(set(labs)) < 2:
            continue
        sil = silhouette_score(Z, labs, metric="euclidean")
        if sil > best["silhouette"]:
            best = {"k": k, "silhouette": sil, "labels": labs}

    if best["labels"] is None:
        best["labels"] = np.ones(len(results), dtype=int)

    km = KMeans(n_clusters=best["k"], n_init=10, random_state=0).fit(Z)
    order = cluster.hierarchy.leaves_list(linkage)

    return {
        "names": names,
        "feature_labels": feature_labels(),
        "Z": linkage.tolist(),
        "dendrogram_order": order.tolist(),
        "k": best["k"],
        "silhouette": round(float(best["silhouette"]), 4),
        "labels": [int(x) for x in best["labels"]],
        "kmeans_labels": [int(x) for x in km.labels_],
        "distances": pairwise_distances(Z, metric="euclidean").tolist(),
    }


def correlation_matrix(results) -> dict[str, Any]:
    metrics = [
        ("file_size", "file size"),
        ("total_reads", "total reads"),
        ("unique_offsets", "unique offsets"),
        ("repeated_reads", "repeated reads"),
        ("bytes_read", "bytes read"),
        ("read_amplification", "amplification"),
        ("coverage_pct", "coverage %"),
        ("block_coverage_pct", "4K block coverage %"),
        ("offset_entropy", "offset entropy"),
        ("sequential", "sequential score"),
        ("passes", "scan passes"),
        ("duration_seconds", "duration (s)"),
        ("region_count", "regions touched"),
    ]
    keys = [k for k, _ in metrics]
    M = np.array([[float(getattr(r, k)) for k in keys] for r in results])
    C = np.corrcoef(M.T)
    return {
        "metrics": [lbl for _, lbl in metrics],
        "keys": keys,
        "matrix": np.nan_to_num(C).tolist(),
    }


# ── common / recurring patterns ────────────────────────────────────────


def region_frequency(results) -> list[dict[str, Any]]:
    """For every PE region name: how many experiments touched it."""
    counts: Counter[str] = Counter()
    bytes_by_region: Counter[str] = Counter()
    reads_by_region: Counter[str] = Counter()
    for r in results:
        for name, ri in r.regions.items():
            counts[name] += 1
            bytes_by_region[name] += ri.bytes_read
            reads_by_region[name] += ri.reads
    n = len(results)
    out = []
    for name in counts:
        out.append(
            {
                "region": name,
                "experiments": counts[name],
                "pct_experiments": round(counts[name] / n * 100, 1),
                "total_reads": reads_by_region[name],
                "total_bytes": bytes_by_region[name],
            }
        )
    out.sort(key=lambda x: x["pct_experiments"], reverse=True)
    return out


def common_region_order(results) -> list[dict[str, Any]]:
    """At each access rank, which region appears and in how many exps."""
    max_rank = max(len(r.regions_in_order) for r in results)
    out = []
    for rank in range(max_rank):
        counts: Counter[str] = Counter()
        for r in results:
            if rank < len(r.regions_in_order):
                counts[r.regions_in_order[rank]] += 1
        out.append(
            {
                "rank": rank + 1,
                "region": counts.most_common(1)[0][0],
                "exps": counts.most_common(1)[0][1],
                "top3": counts.most_common(3),
            }
        )
    return out


def common_offset_bins(results, nbins: int = 64) -> list[dict[str, Any]]:
    """Fraction of experiments that read each normalized offset bin."""
    n = len(results)
    bins_touched = [set() for _ in range(nbins)]
    for r in results:
        seen = {min(int((e["offset"] / r.file_size) * nbins), nbins - 1) for e in r.reads}
        for b in seen:
            bins_touched[b].add(r.exp_id)
    return [
        {"bin": b, "frac": round(len(v) / n, 3), "experiments": len(v)}
        for b, v in enumerate(bins_touched)
    ]


def chunk_size_frequency(results) -> list[dict[str, Any]]:
    n = len(results)
    out = []
    for lo, hi, name in CHUNK_BANDS:
        exps = sum(1 for r in results if r.chunk_dist.get(name, 0) > 0)
        total = sum(r.chunk_dist.get(name, 0) for r in results)
        out.append(
            {
                "band": name,
                "total_reads": total,
                "pct_experiments": round(exps / n * 100, 1),
            }
        )
    return out


def passes_distribution(results) -> Counter[int]:
    return Counter(r.passes for r in results)


def repeated_offset_analysis(results) -> dict[str, Any]:
    """Global repeated-read statistics."""
    total = sum(r.total_reads for r in results)
    unique = sum(r.unique_offsets for r in results)
    repeated = sum(r.repeated_reads for r in results)
    return {
        "total_reads": total,
        "unique_offsets": unique,
        "repeated_reads": repeated,
        "repeated_pct": round(repeated / total * 100, 2) if total else 0.0,
        "mean_repeated_pct": round(
            np.mean([r.repeated_reads / r.total_reads for r in results if r.total_reads]) * 100, 2
        ),
    }


def region_aggregate_stats(results) -> list[dict[str, Any]]:
    """Per-region cross-experiment aggregates (read counts, bytes,
    experiment coverage, average access order, repeated reads, avg size)."""
    n = len(results)
    agg: dict[str, dict[str, Any]] = {}
    for r in results:
        for rank, name in enumerate(r.regions_in_order):
            if name not in r.regions:
                continue
            ri = r.regions[name]
            a = agg.setdefault(
                name,
                {
                    "region": name,
                    "rclass": ri.rclass,
                    "exps": 0,
                    "reads": 0,
                    "bytes": 0,
                    "unique": 0,
                    "repeated": 0,
                    "sum_order": 0,
                    "sizes": [],
                },
            )
            a["exps"] += 1
            a["reads"] += ri.reads
            a["bytes"] += ri.bytes_read
            a["unique"] += ri.unique_offsets
            a["repeated"] += ri.repeated_reads
            a["sum_order"] += rank + 1
            a["sizes"].extend(
                [e["length"] for e in r.reads if _read_hits_region(e, ri)]
            )
    out = []
    for name, a in agg.items():
        sizes = a["sizes"]
        out.append(
            {
                "region": name,
                "rclass": a["rclass"],
                "experiments": a["exps"],
                "pct_experiments": round(a["exps"] / n * 100, 1),
                "total_reads": a["reads"],
                "total_bytes": a["bytes"],
                "avg_bytes_per_exp": round(a["bytes"] / a["exps"], 1) if a["exps"] else 0,
                "repeated_reads": a["repeated"],
                "avg_access_order": round(a["sum_order"] / a["exps"], 1) if a["exps"] else None,
                "avg_read_size": round(np.mean(sizes), 1) if sizes else 0,
            }
        )
    out.sort(key=lambda x: x["total_bytes"], reverse=True)
    return out


def _read_hits_region(e: dict[str, Any], ri) -> bool:
    end = e["offset"] + e["length"]
    return ri.start <= end and e["offset"] <= ri.end + 1


# ── statistical research ───────────────────────────────────────────────


def _ci95(vals: list[float]) -> tuple[float, float, float]:
    a = np.array(vals, dtype=float)
    m = a.mean()
    s = a.std(ddof=1) if len(a) > 1 else 0.0
    n = len(a)
    se = s / math.sqrt(n)
    half = 1.96 * se
    return m, m - half, m + half


def summary_stats(results) -> list[dict[str, Any]]:
    metrics = [
        "file_size", "total_reads", "unique_offsets", "repeated_reads",
        "bytes_read", "read_amplification", "coverage_pct",
        "block_coverage_pct", "offset_entropy", "sequential", "passes",
        "duration_seconds", "region_count", "mean_read", "median_read",
        "std_read", "min_read", "max_read", "phase_count",
    ]
    out = []
    for m in metrics:
        vals = sorted(float(getattr(r, m)) for r in results)
        a = np.array(vals)
        mean, lo, hi = _ci95(vals)
        q1, q2, q3 = np.percentile(a, [25, 50, 75])
        out.append(
            {
                "metric": m,
                "mean": round(mean, 3),
                "median": round(q2, 3),
                "variance": round(a.var(), 2),
                "std": round(a.std(), 3),
                "q1": round(q1, 3),
                "q3": round(q3, 3),
                "min": round(a.min(), 3),
                "max": round(a.max(), 3),
                "ci95_low": round(lo, 3),
                "ci95_high": round(hi, 3),
                "n": len(a),
            }
        )
    return out


# ── anomaly detection ─────────────────────────────────────────────────


def detect_anomalies(results) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    n = len(results)

    z_metrics = [
        ("read_amplification", "amplification"),
        ("duration_seconds", "duration"),
        ("bytes_read", "bytes read"),
        ("total_reads", "total reads"),
        ("offset_entropy", "offset entropy"),
        ("repeated_reads", "repeated reads"),
    ]
    for m, label in z_metrics:
        vals = [float(getattr(r, m)) for r in results]
        mean = np.mean(vals)
        std = np.std(vals)
        if std == 0:
            continue
        for r, v in zip(results, vals):
            z = (v - mean) / std
            if abs(z) >= 2.5:
                anomalies.append(
                    {
                        "exp": r.exp_id,
                        "sample": r.sample,
                        "type": "z-score outlier",
                        "metric": label,
                        "value": round(v, 3),
                        "z": round(z, 2),
                        "reason": f"{label} ({v:.2f}) is {z:+.2f} sigma from dataset mean",
                    }
                )

    # IQR outliers
    for m, label in [
        ("read_amplification", "amplification"),
        ("repeated_reads", "repeated reads"),
        ("duration_seconds", "duration"),
    ]:
        vals = [float(getattr(r, m)) for r in results]
        q1, q3 = np.percentile(vals, [25, 75])
        iqr = q3 - q1
        lo, hi = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        for r, v in zip(results, vals):
            if v < lo or v > hi:
                anomalies.append(
                    {
                        "exp": r.exp_id,
                        "sample": r.sample,
                        "type": "IQR outlier",
                        "metric": label,
                        "value": round(v, 3),
                        "z": None,
                        "reason": f"{label} outside 1.5x IQR range [{lo:.2f},{hi:.2f}]",
                    }
                )

    # Reads beyond EOF
    for r in results:
        if r.read_beyond_eof:
            anomalies.append(
                {
                    "exp": r.exp_id,
                    "sample": r.sample,
                    "type": "offset beyond EOF",
                    "metric": "read_beyond_eof",
                    "value": r.read_beyond_eof,
                    "z": None,
                    "reason": (
                        f"{r.read_beyond_eof} reads extend past the end of the "
                        f"{r.file_size:,}-byte file (request clamped to EOF)"
                    ),
                }
            )

    # Missing phases relative to the common core
    for r in results:
        missing = [p for p in ["Header Inspection", "Directory Parsing"] if p not in r.phase_names]
        if missing:
            anomalies.append(
                {
                    "exp": r.exp_id,
                    "sample": r.sample,
                    "type": "missing phase",
                    "metric": "phases",
                    "value": ", ".join(missing),
                    "z": None,
                    "reason": f"scan lacks the typical phase(s): {', '.join(missing)}",
                }
            )

    # Tiny captures
    for r in results:
        if r.total_reads <= 2:
            anomalies.append(
                {
                    "exp": r.exp_id,
                    "sample": r.sample,
                    "type": "degenerate capture",
                    "metric": "total reads",
                    "value": r.total_reads,
                    "z": None,
                    "reason": "only 2 or fewer SUCCESS reads; scan may have been truncated",
                }
            )

    # Reads at non-4K alignment dominating (possible cacheline probes)
    for r in results:
        unaligned = sum(1 for e in r.reads if e["offset"] % BLOCK != 0)
        if r.total_reads and unaligned / r.total_reads > 0.3:
            anomalies.append(
                {
                    "exp": r.exp_id,
                    "sample": r.sample,
                    "type": "unaligned reads",
                    "metric": "unaligned frac",
                    "value": round(unaligned / r.total_reads, 3),
                    "z": None,
                    "reason": f"{unaligned}/{r.total_reads} reads start at non-4K-aligned offsets",
                }
            )

    anomalies.sort(key=lambda a: (a["exp"], a["type"]))
    return anomalies


def run() -> dict[str, Any]:
    results = load(OUT_DIR / "pipeline_results.json")
    data = {
        "results": [json.loads(json.dumps(r, default=str)) for r in results],
        "region_frequency": region_frequency(results),
        "common_region_order": common_region_order(results),
        "common_offset_bins": common_offset_bins(results),
        "chunk_size_frequency": chunk_size_frequency(results),
        "passes_distribution": dict(sorted(passes_distribution(results).items())),
        "repeated": repeated_offset_analysis(results),
        "region_aggregate": region_aggregate_stats(results),
        "summary_stats": summary_stats(results),
        "correlation": correlation_matrix(results),
        "clustering": cluster_experiments(results),
        "anomalies": detect_anomalies(results),
    }
    with (OUT_DIR / "cross_analysis.json").open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, default=str)
    print(f"cross analysis written: {len(results)} experiments")
    return data


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    run()
