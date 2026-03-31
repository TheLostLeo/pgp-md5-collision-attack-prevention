from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

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


def plot_all_graphs(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> str:
    md5_summary, sha_summary = _suite_pair(md5_summary, sha_summary)

    fig = plt.figure(figsize=(16, 10))
    fig.suptitle(
        "PGP Key Signing with Weak Hash (MD5) vs Prevention (SHA-256)",
        fontsize=15,
        fontweight="bold",
        y=0.99,
    )

    ax1 = plt.subplot(2, 2, 1)
    labels = ["Before (MD5)", "After (SHA-256)"]
    success_rates = [md5_summary.success_rate, sha_summary.success_rate]
    bars = ax1.bar(labels, success_rates, color=["#ff5555", "#55ff55"], edgecolor="black")
    ax1.set_title("1) Attack Success Rate Before vs After", fontweight="bold")
    ax1.set_ylabel("Forgery Success Rate (%)")
    ax1.set_ylim(0, 110)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    for bar in bars:
        y = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontweight="bold")

    ax2 = plt.subplot(2, 2, 2)
    key_sizes, gen_times = benchmark_key_generation((1024, 1536, 2048))
    ax2.plot(key_sizes, gen_times, marker="o", linewidth=2.5, color="#1f4e79")
    ax2.set_title("2) Time vs Key Size (RSA Key Generation)", fontweight="bold")
    ax2.set_xlabel("Key Size (bits)")
    ax2.set_ylabel("Generation Time (seconds)")
    ax2.grid(True, linestyle="--", alpha=0.4)
    for x, y in zip(key_sizes, gen_times):
        ax2.annotate(f"{y:.3f}s", (x, y), textcoords="offset points", xytext=(0, 8), ha="center")

    ax3 = plt.subplot(2, 2, 3)
    metrics = ["Confidentiality", "Integrity", "Authentication"]
    md5_values = [
        md5_summary.confidentiality_rate,
        md5_summary.integrity_rate,
        md5_summary.authentication_rate,
    ]
    sha_values = [
        sha_summary.confidentiality_rate,
        sha_summary.integrity_rate,
        sha_summary.authentication_rate,
    ]
    x = range(len(metrics))
    width = 0.35
    bars_md5 = ax3.bar([i - width / 2 for i in x], md5_values, width, label="MD5", color="#ff9999", edgecolor="black")
    bars_sha = ax3.bar([i + width / 2 for i in x], sha_values, width, label="SHA-256", color="#99e699", edgecolor="black")
    ax3.set_title("3) Confidentiality / Integrity / Authentication", fontweight="bold")
    ax3.set_ylabel("Security Rate (%)")
    ax3.set_ylim(0, 110)
    ax3.set_xticks(list(x))
    ax3.set_xticklabels(metrics)
    ax3.legend()
    ax3.grid(axis="y", linestyle="--", alpha=0.4)
    for bars in (bars_md5, bars_sha):
        for bar in bars:
            y = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontsize=9)

    ax4 = plt.subplot(2, 2, 4)
    latency_labels = ["Hash", "Sign", "Verify"]
    md5_lat = [
        md5_summary.avg_hash_time_ms,
        md5_summary.avg_sign_time_ms,
        md5_summary.avg_verify_time_ms,
    ]
    sha_lat = [
        sha_summary.avg_hash_time_ms,
        sha_summary.avg_sign_time_ms,
        sha_summary.avg_verify_time_ms,
    ]
    x = range(len(latency_labels))
    bars_md5 = ax4.bar([i - width / 2 for i in x], md5_lat, width, label="MD5", color="#ff5555", edgecolor="black")
    bars_sha = ax4.bar([i + width / 2 for i in x], sha_lat, width, label="SHA-256", color="#55ff55", edgecolor="black")
    ax4.set_title("4) Attack vs Prevention Latency Overhead", fontweight="bold")
    ax4.set_ylabel("Latency (ms)")
    ax4.set_xticks(list(x))
    ax4.set_xticklabels(latency_labels)
    ax4.legend()
    ax4.grid(axis="y", linestyle="--", alpha=0.4)
    for bars in (bars_md5, bars_sha):
        for bar in bars:
            y = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width() / 2, y + max(md5_lat + sha_lat) * 0.03, f"{y:.3f}", ha="center", fontsize=9)

    plt.tight_layout(rect=[0, 0, 1, 0.97])

    out_dir = _ensure_graph_dir()
    out_file = out_dir / "project_required_graphs.png"
    plt.savefig(out_file, dpi=150, bbox_inches="tight")
    plt.show()
    plt.close(fig)

    return str(out_file)


def plot_attack_success(
    md5_summary: Optional[ExperimentSummary] = None,
    sha_summary: Optional[ExperimentSummary] = None,
) -> str:
    md5_summary, sha_summary = _suite_pair(md5_summary, sha_summary)

    plt.figure(figsize=(8, 5))
    labels = ["MD5 (Before)", "SHA-256 (After)"]
    rates = [md5_summary.success_rate, sha_summary.success_rate]
    bars = plt.bar(labels, rates, color=["#ff5555", "#55ff55"], edgecolor="black")
    plt.title("Attack Success Rate Before vs After", fontweight="bold")
    plt.ylabel("Forgery Success Rate (%)")
    plt.ylim(0, 110)
    plt.grid(axis="y", linestyle="--", alpha=0.4)
    for bar in bars:
        y = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, y + 2, f"{y:.1f}%", ha="center", fontweight="bold")

    out_dir = _ensure_graph_dir()
    out_file = out_dir / "graph_success_rate.png"
    plt.tight_layout()
    plt.savefig(out_file, dpi=150)
    plt.show()
    plt.close()
    return str(out_file)


def plot_time_vs_keysize() -> str:
    sizes, times = benchmark_key_generation((1024, 1536, 2048))

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, times, marker="o", linewidth=2.5, color="#1f4e79")
    plt.title("Time vs Key Size", fontweight="bold")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Generation Time (seconds)")
    plt.grid(True, linestyle="--", alpha=0.4)
    for x, y in zip(sizes, times):
        plt.annotate(f"{y:.3f}s", (x, y), textcoords="offset points", xytext=(0, 8), ha="center")

    out_dir = _ensure_graph_dir()
    out_file = out_dir / "graph_time_vs_size.png"
    plt.tight_layout()
    plt.savefig(out_file, dpi=150)
    plt.show()
    plt.close()
    return str(out_file)


if __name__ == "__main__":
    plot_all_graphs()
