from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, Tuple

import matplotlib.pyplot as plt

from src.attack.experiment_engine import (
    ExperimentSummary,
    benchmark_key_generation,
    run_forgery_suite,
)


def _ensure_graph_dir() -> Path:
    out_dir = Path("outputs/graphs")
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _suite_pair(
    md5_summary: Optional[ExperimentSummary], sha_summary: Optional[ExperimentSummary]
) -> Tuple[ExperimentSummary, ExperimentSummary]:
    if md5_summary is None:
        md5_summary = run_forgery_suite(mode="MD5", total_tests=25)
    if sha_summary is None:
        sha_summary = run_forgery_suite(mode="SHA-256", total_tests=25)
    return md5_summary, sha_summary


def _save_fig(fig: plt.Figure, file_name: str) -> str:
    out_file = _ensure_graph_dir() / file_name
    fig.savefig(out_file, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(out_file)


def _build_mandatory_1_success(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = ["Before (MD5)", "After (SHA-256)"]
    values = [md5_summary.success_rate, sha_summary.success_rate]
    bars = ax.bar(labels, values, color=["#ff5555", "#55ff55"], edgecolor="black")
    ax.set_title("Mandatory 1: Attack Success Rate Before vs After", fontweight="bold")
    ax.set_ylabel("Forgery Success Rate (%)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    for bar in bars:
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontweight="bold")
    return _save_fig(fig, "mandatory_1_success_rate.png")


def _build_mandatory_2_time() -> str:
    sizes, times = benchmark_key_generation((1024, 1536, 2048))
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(sizes, times, marker="o", linewidth=2.5, color="#1f4e79")
    ax.set_title("Mandatory 2: Time vs Key Size", fontweight="bold")
    ax.set_xlabel("Key Size (bits)")
    ax.set_ylabel("Generation Time (seconds)")
    ax.grid(True, linestyle="--", alpha=0.4)
    for x, y in zip(sizes, times):
        ax.annotate(f"{y:.3f}s", (x, y), textcoords="offset points", xytext=(0, 8), ha="center")
    return _save_fig(fig, "mandatory_2_time_vs_key_size.png")


def _build_mandatory_3_cia(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(9, 5))
    metrics = ["Confidentiality", "Integrity", "Authentication"]
    md5_vals = [
        md5_summary.confidentiality_rate,
        md5_summary.integrity_rate,
        md5_summary.authentication_rate,
    ]
    sha_vals = [
        sha_summary.confidentiality_rate,
        sha_summary.integrity_rate,
        sha_summary.authentication_rate,
    ]
    x = range(len(metrics))
    width = 0.35
    bars_md5 = ax.bar([i - width / 2 for i in x], md5_vals, width, label="MD5", color="#ff9999", edgecolor="black")
    bars_sha = ax.bar([i + width / 2 for i in x], sha_vals, width, label="SHA-256", color="#99e699", edgecolor="black")
    ax.set_title("Mandatory 3: Confidentiality / Integrity / Authentication", fontweight="bold")
    ax.set_ylabel("Security Rate (%)")
    ax.set_ylim(0, 110)
    ax.set_xticks(list(x))
    ax.set_xticklabels(metrics)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    for bars in (bars_md5, bars_sha):
        for bar in bars:
            y = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontsize=9)
    return _save_fig(fig, "mandatory_3_cia_rates.png")


def _build_mandatory_4_latency(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(9, 5))
    labels = ["Hash", "Sign", "Verify"]
    md5_vals = [
        md5_summary.avg_hash_time_ms,
        md5_summary.avg_sign_time_ms,
        md5_summary.avg_verify_time_ms,
    ]
    sha_vals = [
        sha_summary.avg_hash_time_ms,
        sha_summary.avg_sign_time_ms,
        sha_summary.avg_verify_time_ms,
    ]
    x = range(len(labels))
    width = 0.35
    bars_md5 = ax.bar([i - width / 2 for i in x], md5_vals, width, label="MD5", color="#ff5555", edgecolor="black")
    bars_sha = ax.bar([i + width / 2 for i in x], sha_vals, width, label="SHA-256", color="#55ff55", edgecolor="black")
    ax.set_title("Mandatory 4: Attack vs Prevention Latency Overhead", fontweight="bold")
    ax.set_ylabel("Latency (ms)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    max_val = max(md5_vals + sha_vals) if (md5_vals + sha_vals) else 0.0
    for bars in (bars_md5, bars_sha):
        for bar in bars:
            y = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, y + max_val * 0.03 + 0.001, f"{y:.3f}", ha="center", fontsize=9)
    return _save_fig(fig, "mandatory_4_latency_overhead.png")


def _build_mandatory_dashboard(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle(
        "PGP Key Signing with Weak Hash (MD5) vs SHA-256 Prevention - Mandatory Dashboard",
        fontsize=15,
        fontweight="bold",
        y=0.99,
    )

    ax1 = plt.subplot(2, 2, 1)
    labels = ["Before (MD5)", "After (SHA-256)"]
    values = [md5_summary.success_rate, sha_summary.success_rate]
    bars = ax1.bar(labels, values, color=["#ff5555", "#55ff55"], edgecolor="black")
    ax1.set_title("1) Attack Success Rate Before vs After", fontweight="bold")
    ax1.set_ylabel("Forgery Success Rate (%)")
    ax1.set_ylim(0, 110)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    for bar in bars:
        y = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontweight="bold")

    ax2 = plt.subplot(2, 2, 2)
    sizes, times = benchmark_key_generation((1024, 1536, 2048))
    ax2.plot(sizes, times, marker="o", linewidth=2.5, color="#1f4e79")
    ax2.set_title("2) Time vs Key Size", fontweight="bold")
    ax2.set_xlabel("Key Size (bits)")
    ax2.set_ylabel("Generation Time (seconds)")
    ax2.grid(True, linestyle="--", alpha=0.4)

    ax3 = plt.subplot(2, 2, 3)
    metrics = ["Confidentiality", "Integrity", "Authentication"]
    md5_vals = [md5_summary.confidentiality_rate, md5_summary.integrity_rate, md5_summary.authentication_rate]
    sha_vals = [sha_summary.confidentiality_rate, sha_summary.integrity_rate, sha_summary.authentication_rate]
    x = range(len(metrics))
    width = 0.35
    ax3.bar([i - width / 2 for i in x], md5_vals, width, label="MD5", color="#ff9999", edgecolor="black")
    ax3.bar([i + width / 2 for i in x], sha_vals, width, label="SHA-256", color="#99e699", edgecolor="black")
    ax3.set_title("3) CIA Rate Comparison", fontweight="bold")
    ax3.set_ylabel("Security Rate (%)")
    ax3.set_ylim(0, 110)
    ax3.set_xticks(list(x))
    ax3.set_xticklabels(metrics)
    ax3.legend()
    ax3.grid(axis="y", linestyle="--", alpha=0.4)

    ax4 = plt.subplot(2, 2, 4)
    labels = ["Hash", "Sign", "Verify"]
    md5_lat = [md5_summary.avg_hash_time_ms, md5_summary.avg_sign_time_ms, md5_summary.avg_verify_time_ms]
    sha_lat = [sha_summary.avg_hash_time_ms, sha_summary.avg_sign_time_ms, sha_summary.avg_verify_time_ms]
    x = range(len(labels))
    ax4.bar([i - width / 2 for i in x], md5_lat, width, label="MD5", color="#ff5555", edgecolor="black")
    ax4.bar([i + width / 2 for i in x], sha_lat, width, label="SHA-256", color="#55ff55", edgecolor="black")
    ax4.set_title("4) Latency Overhead", fontweight="bold")
    ax4.set_ylabel("Latency (ms)")
    ax4.set_xticks(list(x))
    ax4.set_xticklabels(labels)
    ax4.legend()
    ax4.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    return _save_fig(fig, "project_required_graphs.png")


def _build_additional_1_per_test_timeline(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(10, 5))
    md5_points = [1 if r.signature_valid else 0 for r in md5_summary.results]
    sha_points = [1 if r.signature_valid else 0 for r in sha_summary.results]
    cases = list(range(1, len(md5_points) + 1))
    ax.plot(cases, md5_points, marker="o", linewidth=1.8, color="#ef4444", label="MD5")
    ax.plot(cases, sha_points, marker="o", linewidth=1.8, color="#22c55e", label="SHA-256")
    ax.set_title("Additional 1: Per-Test Forgery Outcome Timeline", fontweight="bold")
    ax.set_xlabel("Test Case")
    ax.set_ylabel("Forgery Accepted (1) / Blocked (0)")
    ax.set_yticks([0, 1])
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend()
    return _save_fig(fig, "additional_1_per_test_timeline.png")


def _build_additional_2_forgery_by_keysize(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(9, 5))
    md5_counts = defaultdict(int)
    sha_counts = defaultdict(int)
    for result in md5_summary.results:
        if result.signature_valid:
            md5_counts[result.key_size] += 1
    for result in sha_summary.results:
        if result.signature_valid:
            sha_counts[result.key_size] += 1

    key_sizes = sorted({r.key_size for r in md5_summary.results + sha_summary.results})
    x = range(len(key_sizes))
    width = 0.35
    md5_vals = [md5_counts[size] for size in key_sizes]
    sha_vals = [sha_counts[size] for size in key_sizes]

    ax.bar([i - width / 2 for i in x], md5_vals, width, label="MD5", color="#f87171", edgecolor="black")
    ax.bar([i + width / 2 for i in x], sha_vals, width, label="SHA-256", color="#4ade80", edgecolor="black")
    ax.set_title("Additional 2: Forgery Count by Key Size", fontweight="bold")
    ax.set_xlabel("Key Size (bits)")
    ax.set_ylabel("Successful Forgeries")
    ax.set_xticks(list(x))
    ax.set_xticklabels([str(size) for size in key_sizes])
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend()
    return _save_fig(fig, "additional_2_forgery_by_key_size.png")


def _build_additional_3_security_improvement(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(8, 5))
    improvement = md5_summary.success_rate - sha_summary.success_rate
    ax.bar(["Forgery Reduction"], [improvement], color="#2563eb", edgecolor="black")
    ax.set_title("Additional 3: Security Improvement Percentage", fontweight="bold")
    ax.set_ylabel("Improvement (%)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.text(0, improvement + 2, f"{improvement:.1f}%", ha="center", fontweight="bold")
    return _save_fig(fig, "additional_3_security_improvement.png")


def _build_additional_4_cumulative_success(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(10, 5))
    md5_cumulative = []
    sha_cumulative = []
    md5_count = 0
    sha_count = 0

    for idx, result in enumerate(md5_summary.results, start=1):
        if result.signature_valid:
            md5_count += 1
        md5_cumulative.append((md5_count / idx) * 100)

    for idx, result in enumerate(sha_summary.results, start=1):
        if result.signature_valid:
            sha_count += 1
        sha_cumulative.append((sha_count / idx) * 100)

    cases = list(range(1, len(md5_cumulative) + 1))
    ax.plot(cases, md5_cumulative, color="#dc2626", linewidth=2.2, label="MD5 Cumulative Success %")
    ax.plot(cases, sha_cumulative, color="#16a34a", linewidth=2.2, label="SHA-256 Cumulative Success %")
    ax.set_title("Additional 4: Cumulative Forgery Success Curve", fontweight="bold")
    ax.set_xlabel("Test Case")
    ax.set_ylabel("Cumulative Success Rate (%)")
    ax.set_ylim(0, 110)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend()
    return _save_fig(fig, "additional_4_cumulative_success_curve.png")


def _build_additional_5_latency_variance(md5_summary: ExperimentSummary, sha_summary: ExperimentSummary) -> str:
    fig, ax = plt.subplots(figsize=(11, 5))

    md5_hash = [r.hash_time_ms for r in md5_summary.results]
    md5_sign = [r.sign_time_ms for r in md5_summary.results]
    md5_verify = [r.verify_time_ms for r in md5_summary.results]
    sha_hash = [r.hash_time_ms for r in sha_summary.results]
    sha_sign = [r.sign_time_ms for r in sha_summary.results]
    sha_verify = [r.verify_time_ms for r in sha_summary.results]

    data = [md5_hash, md5_sign, md5_verify, sha_hash, sha_sign, sha_verify]
    labels = ["MD5 Hash", "MD5 Sign", "MD5 Verify", "SHA Hash", "SHA Sign", "SHA Verify"]

    ax.boxplot(data, patch_artist=True)
    ax.set_title("Additional 5: Latency Variance (Boxplot)", fontweight="bold")
    ax.set_ylabel("Latency (ms)")
    ax.set_xticklabels(labels, rotation=20)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    return _save_fig(fig, "additional_5_latency_variance_boxplot.png")


def export_graph_package(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> Dict[str, str]:
    md5_summary, sha_summary = _suite_pair(md5_summary, sha_summary)

    outputs: Dict[str, str] = {}

    outputs["mandatory_1_success_rate"] = _build_mandatory_1_success(md5_summary, sha_summary)
    outputs["mandatory_2_time_vs_key_size"] = _build_mandatory_2_time()
    outputs["mandatory_3_cia_rates"] = _build_mandatory_3_cia(md5_summary, sha_summary)
    outputs["mandatory_4_latency_overhead"] = _build_mandatory_4_latency(md5_summary, sha_summary)
    outputs["mandatory_dashboard_4in1"] = _build_mandatory_dashboard(md5_summary, sha_summary)

    outputs["additional_1_per_test_timeline"] = _build_additional_1_per_test_timeline(md5_summary, sha_summary)
    outputs["additional_2_forgery_by_key_size"] = _build_additional_2_forgery_by_keysize(md5_summary, sha_summary)
    outputs["additional_3_security_improvement"] = _build_additional_3_security_improvement(md5_summary, sha_summary)
    outputs["additional_4_cumulative_success_curve"] = _build_additional_4_cumulative_success(md5_summary, sha_summary)
    outputs["additional_5_latency_variance_boxplot"] = _build_additional_5_latency_variance(md5_summary, sha_summary)

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
    return _build_mandatory_2_time()


if __name__ == "__main__":
    files = export_graph_package()
    for name, path in files.items():
        print(f"{name}: {path}")
