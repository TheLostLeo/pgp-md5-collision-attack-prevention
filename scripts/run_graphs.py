from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.attack.experiment_engine import run_forgery_suite
from src.analysis.graphs import export_graph_package


if __name__ == "__main__":
    md5_summary = run_forgery_suite(mode="MD5", total_tests=25)
    sha_summary = run_forgery_suite(mode="SHA-256", total_tests=25)
    generated = export_graph_package(md5_summary, sha_summary)
    for key, path in generated.items():
        print(f"{key}: {path}")
