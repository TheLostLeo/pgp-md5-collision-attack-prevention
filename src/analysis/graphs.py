from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple

import matplotlib.pyplot as plt

from src.attack.experiment_engine import (
    ExperimentSummary,
    SECURE_PREVENTION_MODES,
    benchmark_key_generation,
    run_forgery_suite,
)


METHOD_COLORS = {
    "MD5": "#ef4444",
    "SHA-256": "#22c55e",
    "SHA3-256": "#14b8a6",
    "SHA-512": "#3b82f6",
    "BLAKE2B-256": "#a855f7",
}


def _ensure_graph_dir() -> Path:
    out_dir = Path("outputs/graphs")
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _save_fig(fig: plt.Figure, file_name: str) -> str:
    out_file = _ensure_graph_dir() / file_name
    fig.savefig(out_file, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(out_file)


def _suite_pair(
    md5_summary: Optional[ExperimentSummary], sha_summary: Optional[ExperimentSummary]
) -> Tuple[ExperimentSummary, ExperimentSummary]:
    if md5_summary is None:
        md5_summary = run_forgery_suite(mode="MD5", total_tests=25)
    if sha_summary is None:
        sha_summary = run_forgery_suite(mode="SHA-256", total_tests=25)
    return md5_summary, sha_summary


def _comparison_summaries(
    md5_summary: ExperimentSummary,
    sha_summary: ExperimentSummary,
) -> Dict[str, ExperimentSummary]:
    summaries: Dict[str, ExperimentSummary] = {"MD5": md5_summary, "SHA-256": sha_summary}
    for mode in SECURE_PREVENTION_MODES:
        if mode not in summaries:
            summaries[mode] = run_forgery_suite(mode=mode, total_tests=25)
    return summaries


def _build_mandatory_1_success(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]
    rates = [comparison[m].success_rate for m in methods]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(methods, rates, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax.set_title("Mandatory 1: Attack Success Rate (MD5 vs 4 Prevention Methods)", fontweight="bold")
    ax.set_ylabel("Forgery Success Rate (%)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    for bar in bars:
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + 1.8, f"{y:.1f}%", ha="center", fontsize=9)

    return _save_fig(fig, "mandatory_1_success_rate.png")


def _build_mandatory_2_time(comparison: Dict[str, ExperimentSummary]) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    sizes, times = benchmark_key_generation((1024, 1536, 2048))
    ax1 = axes[0]
    ax1.plot(sizes, times, marker="o", linewidth=2.5, color="#1f4e79")
    ax1.set_title("Mandatory 2A: Time vs Key Size", fontweight="bold")
    ax1.set_xlabel("RSA Key Size (bits)")
    ax1.set_ylabel("Generation Time (seconds)")
    ax1.grid(True, linestyle="--", alpha=0.4)
    for x, y in zip(sizes, times):
        ax1.annotate(f"{y:.3f}s", (x, y), textcoords="offset points", xytext=(0, 8), ha="center")

    methods = ["MD5", *SECURE_PREVENTION_MODES]
    hash_times = [comparison[m].avg_hash_time_ms for m in methods]
    ax2 = axes[1]
    bars = ax2.bar(methods, hash_times, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax2.set_title("Mandatory 2B: Hash Time vs Algorithm Parameter", fontweight="bold")
    ax2.set_xlabel("Algorithm")
    ax2.set_ylabel("Average Hash Time (ms)")
    ax2.grid(axis="y", linestyle="--", alpha=0.4)
    max_hash = max(hash_times) if hash_times else 0.0
    for bar in bars:
        y = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2, y + max_hash * 0.05 + 0.0002, f"{y:.4f}", ha="center", fontsize=8)

    fig.suptitle("Mandatory 2: Time vs Key / Parameter Size", fontsize=13, fontweight="bold")
    plt.tight_layout(rect=[0, 0, 1, 0.94])
    return _save_fig(fig, "mandatory_2_time_vs_key_size.png")


def _build_mandatory_3_cia(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]
    integrity = [comparison[m].integrity_rate for m in methods]
    authentication = [comparison[m].authentication_rate for m in methods]
    confidentiality = [comparison[m].confidentiality_rate for m in methods]

    fig, ax = plt.subplots(figsize=(11, 5))
    x = range(len(methods))
    width = 0.25

    bars_c = ax.bar([i - width for i in x], confidentiality, width, label="Confidentiality", color="#38bdf8", edgecolor="black")
    bars_i = ax.bar([i for i in x], integrity, width, label="Integrity", color="#f59e0b", edgecolor="black")
    bars_a = ax.bar([i + width for i in x], authentication, width, label="Authentication", color="#10b981", edgecolor="black")

    ax.set_title("Mandatory 3: CIA Rate Comparison (MD5 vs 4 Prevention Methods)", fontweight="bold")
    ax.set_ylabel("Security Rate (%)")
    ax.set_ylim(0, 110)
    ax.set_xticks(list(x))
    ax.set_xticklabels(methods)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    for bars in (bars_c, bars_i, bars_a):
        for bar in bars:
            y = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, y + 1.2, f"{y:.1f}", ha="center", fontsize=7)

    return _save_fig(fig, "mandatory_3_cia_rates.png")


def _build_mandatory_4_latency(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]

    fig, ax = plt.subplots(figsize=(11, 5))
    labels = ["Hash", "Sign", "Verify"]
    x = range(len(labels))
    width = 0.16

    for idx, method in enumerate(methods):
        vals = [
            comparison[method].avg_hash_time_ms,
            comparison[method].avg_sign_time_ms,
            comparison[method].avg_verify_time_ms,
        ]
        offset = (idx - 2) * width
        ax.bar([i + offset for i in x], vals, width, label=method, color=METHOD_COLORS[method], edgecolor="black")

    ax.set_title("Mandatory 4: Latency Overhead (MD5 vs 4 Prevention Methods)", fontweight="bold")
    ax.set_ylabel("Latency (ms)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(ncol=3, fontsize=8)

    return _save_fig(fig, "mandatory_4_latency_overhead.png")


def _build_mandatory_dashboard(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]

    fig = plt.figure(figsize=(16, 10))
    fig.suptitle(
        "Mandatory Dashboard: MD5 vs 4 Prevention Methods",
        fontsize=15,
        fontweight="bold",
        y=0.99,
    )

    ax1 = plt.subplot(2, 2, 1)
    rates = [comparison[m].success_rate for m in methods]
    ax1.bar(methods, rates, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax1.set_title("1) Attack Success Rate", fontweight="bold")
    ax1.set_ylim(0, 110)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)

    ax2 = plt.subplot(2, 2, 2)
    sizes, times = benchmark_key_generation((1024, 1536, 2048))
    ax2.plot(sizes, times, marker="o", linewidth=2.5, color="#1f4e79")
    ax2.set_title("2) Time vs Key Size", fontweight="bold")
    ax2.set_xlabel("Key Size (bits)")
    ax2.set_ylabel("Seconds")
    ax2.grid(True, linestyle="--", alpha=0.4)

    ax3 = plt.subplot(2, 2, 3)
    integrity = [comparison[m].integrity_rate for m in methods]
    auth = [comparison[m].authentication_rate for m in methods]
    x = range(len(methods))
    width = 0.35
    ax3.bar([i - width / 2 for i in x], integrity, width, label="Integrity", color="#f59e0b", edgecolor="black")
    ax3.bar([i + width / 2 for i in x], auth, width, label="Authentication", color="#10b981", edgecolor="black")
    ax3.set_title("3) CIA (I/A focus)", fontweight="bold")
    ax3.set_ylim(0, 110)
    ax3.set_xticks(list(x))
    ax3.set_xticklabels(methods)
    ax3.grid(axis="y", linestyle="--", alpha=0.4)
    ax3.legend()

    ax4 = plt.subplot(2, 2, 4)
    hash_times = [comparison[m].avg_hash_time_ms for m in methods]
    ax4.bar(methods, hash_times, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax4.set_title("4) Hash Latency", fontweight="bold")
    ax4.set_ylabel("ms")
    ax4.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    return _save_fig(fig, "project_required_graphs.png")


def _build_additional_1_method_success(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]
    rates = [comparison[m].success_rate for m in methods]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(methods, rates, marker="o", linewidth=2.5, color="#0ea5e9")
    ax.set_title("Additional 1: Method-wise Forgery Success Trend", fontweight="bold")
    ax.set_ylabel("Forgery Success Rate (%)")
    ax.grid(True, linestyle="--", alpha=0.4)
    return _save_fig(fig, "additional_1_method_success_trend.png")


def _build_additional_2_hash_latency(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]
    hash_ms = [comparison[m].avg_hash_time_ms for m in methods]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(methods, hash_ms, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax.set_title("Additional 2: Hash Latency Comparison (MD5 vs 4 Prevention)", fontweight="bold")
    ax.set_ylabel("Average Hash Time (ms)")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    max_hash = max(hash_ms) if hash_ms else 0.0
    for bar in bars:
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + max_hash * 0.05 + 0.0002, f"{y:.4f}", ha="center", fontsize=8)
    return _save_fig(fig, "additional_2_hash_latency_comparison.png")


def _build_additional_3_e2e_latency(comparison: Dict[str, ExperimentSummary]) -> str:
    methods = ["MD5", *SECURE_PREVENTION_MODES]
    total_ms = [
        comparison[m].avg_hash_time_ms + comparison[m].avg_sign_time_ms + comparison[m].avg_verify_time_ms
        for m in methods
    ]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(methods, total_ms, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax.set_title("Additional 3: End-to-End Latency (Hash+Sign+Verify)", fontweight="bold")
    ax.set_ylabel("Average Total Latency (ms)")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    max_total = max(total_ms) if total_ms else 0.0
    for bar in bars:
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + max_total * 0.03 + 0.0002, f"{y:.3f}", ha="center", fontsize=8)
    return _save_fig(fig, "additional_3_e2e_latency_comparison.png")


def _build_additional_4_improvement_vs_md5(comparison: Dict[str, ExperimentSummary]) -> str:
    md5_rate = comparison["MD5"].success_rate
    methods = list(SECURE_PREVENTION_MODES)
    reduction = [md5_rate - comparison[m].success_rate for m in methods]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(methods, reduction, color=[METHOD_COLORS[m] for m in methods], edgecolor="black")
    ax.set_title("Additional 4: Security Improvement vs MD5 Baseline", fontweight="bold")
    ax.set_ylabel("Forgery Reduction (%)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    for bar in bars:
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + 1.2, f"{y:.1f}%", ha="center", fontsize=9)
    return _save_fig(fig, "additional_4_improvement_vs_md5.png")


def export_graph_package(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> Dict[str, str]:
    md5_summary, sha_summary = _suite_pair(md5_summary, sha_summary)
    comparison = _comparison_summaries(md5_summary, sha_summary)

    outputs: Dict[str, str] = {}

    outputs["mandatory_1_success_rate"] = _build_mandatory_1_success(comparison)
    outputs["mandatory_2_time_vs_key_size"] = _build_mandatory_2_time(comparison)
    outputs["mandatory_3_cia_rates"] = _build_mandatory_3_cia(comparison)
    outputs["mandatory_4_latency_overhead"] = _build_mandatory_4_latency(comparison)
    outputs["mandatory_dashboard_4in1"] = _build_mandatory_dashboard(comparison)

    outputs["additional_1_method_success_trend"] = _build_additional_1_method_success(comparison)
    outputs["additional_2_hash_latency_comparison"] = _build_additional_2_hash_latency(comparison)
    outputs["additional_3_e2e_latency_comparison"] = _build_additional_3_e2e_latency(comparison)
    outputs["additional_4_improvement_vs_md5"] = _build_additional_4_improvement_vs_md5(comparison)

    return outputs


def plot_all_graphs(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> str:
    outputs = export_graph_package(md5_summary, sha_summary)
    return outputs["mandatory_dashboard_4in1"]


def plot_attack_success(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> str:
    outputs = export_graph_package(md5_summary, sha_summary)
    return outputs["mandatory_1_success_rate"]


def plot_time_vs_keysize() -> str:
    outputs = export_graph_package()
    return outputs["mandatory_2_time_vs_key_size"]


if __name__ == "__main__":
    files = export_graph_package()
    for name, path in files.items():
        print(f"{name}: {path}")
