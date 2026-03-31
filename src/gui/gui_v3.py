from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading

from src.analysis.review1_graphs import plot_all_graphs
from src.attack.experiment_engine import (
    ExperimentSummary,
    TestCaseResult,
    run_forgery_suite,
)
from src.core.rsa_core import generate_keypair


class PGPAttackGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PGP Key Signing: MD5 Collision Forgery vs SHA-256 Prevention")
        self.root.geometry("1120x760")

        self.current_mode = "MD5"
        self.public_key = None
        self.private_key = None
        self.last_md5_summary: ExperimentSummary | None = None
        self.last_sha_summary: ExperimentSummary | None = None

        self.var_pub_key = tk.StringVar(value="Not generated yet...")
        self.var_priv_key = tk.StringVar(value="Not generated yet...")
        self.var_hash_legit = tk.StringVar(value="Run tests to view latest digest")
        self.var_hash_malic = tk.StringVar(value="Run tests to view latest digest")
        self.var_mode = tk.StringVar(value="Current Mode: MD5 (Vulnerable)")
        self._suite_running = False

        self._build_ui()
        self.log("System initialized. Click Generate Keys to begin.", "INFO")

    def _build_ui(self) -> None:
        top = tk.Frame(self.root, bg="#1e2a38", pady=10)
        top.pack(fill=tk.X)

        self.btn_gen_keys = tk.Button(
            top,
            text="1. Generate Keys / Parameters",
            command=self.generate_keys,
            bg="#ecf0f1",
            width=28,
            font=("Arial", 10, "bold"),
        )
        self.btn_gen_keys.grid(row=0, column=0, padx=10, pady=4)

        self.btn_run_attack = tk.Button(
            top,
            text="2. Run Attack (Collision)",
            command=self.run_attack,
            bg="#ffcccc",
            width=28,
            font=("Arial", 10, "bold"),
        )
        self.btn_run_attack.grid(row=0, column=1, padx=10, pady=4)

        self.btn_prevention = tk.Button(
            top,
            text="3. Apply Prevention (SHA-256)",
            command=self.apply_prevention,
            bg="#ccffcc",
            width=28,
            font=("Arial", 10, "bold"),
        )
        self.btn_prevention.grid(row=0, column=2, padx=10, pady=4)

        self.btn_graphs = tk.Button(
            top,
            text="4. Show Graphs",
            command=self.show_graphs,
            bg="#cce5ff",
            width=28,
            font=("Arial", 10, "bold"),
        )
        self.btn_graphs.grid(row=0, column=3, padx=10, pady=4)

        state = tk.Label(self.root, textvariable=self.var_mode, font=("Arial", 11, "bold"), fg="#2c3e50")
        state.pack(fill=tk.X, padx=10, pady=(8, 0))

        dashboard = tk.LabelFrame(self.root, text=" Cryptographic State Dashboard ", padx=10, pady=10)
        dashboard.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(dashboard, text="Public Key (e, n):", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="nw", padx=8, pady=5)
        tk.Entry(dashboard, textvariable=self.var_pub_key, state="readonly", width=95).grid(row=0, column=1, padx=8, pady=5, sticky="ew")

        tk.Label(dashboard, text="Private Key (d, n):", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="nw", padx=8, pady=5)
        tk.Entry(dashboard, textvariable=self.var_priv_key, state="readonly", width=95).grid(row=1, column=1, padx=8, pady=5, sticky="ew")

        tk.Label(dashboard, text="Latest Legitimate Hash:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", padx=8, pady=5)
        tk.Entry(dashboard, textvariable=self.var_hash_legit, state="readonly", width=95).grid(row=2, column=1, padx=8, pady=5, sticky="ew")

        tk.Label(dashboard, text="Latest Malicious Hash:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky="w", padx=8, pady=5)
        tk.Entry(dashboard, textvariable=self.var_hash_malic, state="readonly", width=95).grid(row=3, column=1, padx=8, pady=5, sticky="ew")

        dashboard.columnconfigure(1, weight=1)

        log_frame = tk.LabelFrame(self.root, text=" Execution Log ", padx=6, pady=6)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#111827",
            fg="#e5e7eb",
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)

        self.log_area.tag_config("INFO", foreground="#d1d5db")
        self.log_area.tag_config("RED", foreground="#ef4444", font=("Consolas", 10, "bold"))
        self.log_area.tag_config("GREEN", foreground="#22c55e", font=("Consolas", 10, "bold"))
        self.log_area.tag_config("HIGHLIGHT", foreground="#f59e0b", font=("Consolas", 10, "bold"))

    def log(self, message: str, tag: str = "INFO") -> None:
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)
        self.root.update_idletasks()

    def generate_keys(self) -> None:
        self.log("[SYSTEM] Generating RSA keys for dashboard display (1024-bit)...", "INFO")
        self.public_key, self.private_key = generate_keypair(1024)
        self.var_pub_key.set(f"e={self.public_key[0]}, n={self.public_key[1]}")
        self.var_priv_key.set(f"d={self.private_key[0]}, n={self.private_key[1]}")
        self.log("[SYSTEM] Keys generated successfully.", "GREEN")

    def run_attack(self) -> None:
        if self.public_key is None:
            messagebox.showwarning("Missing Keys", "Please click Generate Keys first.")
            return

        if self._suite_running:
            self.log("[SYSTEM] Please wait. A test suite is already running...", "HIGHLIGHT")
            return

        self.log("", "INFO")
        self.log("================== ATTACK EXECUTION ==================", "INFO")

        mode = "MD5" if self.current_mode == "MD5" else "SHA-256"
        if mode == "MD5":
            self.log("[ATTACK] Running 25 automated MD5 collision-forgery test cases...", "HIGHLIGHT")
        else:
            self.log("[SECURE] Running 25 automated SHA-256 prevention test cases...", "GREEN")

        self._suite_running = True
        self._set_controls_state(False)
        threading.Thread(target=self._run_suite_worker, args=(mode,), daemon=True).start()

    def _run_suite_worker(self, mode: str) -> None:
        try:
            def progress(case_result: TestCaseResult) -> None:
                self.root.after(0, self._log_case_progress, case_result)

            summary = run_forgery_suite(mode=mode, total_tests=25, case_callback=progress)
            self.root.after(0, self._on_suite_complete, summary)
        except Exception as exc:
            self.root.after(0, self._on_suite_error, str(exc))

    def _log_case_progress(self, result: TestCaseResult) -> None:
        color = "RED" if result.signature_valid else "GREEN"
        status = "FORGERY ACCEPTED" if result.signature_valid else "FORGERY BLOCKED"
        self.log(
            f"Case {result.case_id:02d}/25 | {result.key_label} | {status} | {result.note}",
            color,
        )

    def _on_suite_complete(self, summary: ExperimentSummary) -> None:
        if summary.mode == "MD5":
            self.last_md5_summary = summary
        else:
            self.last_sha_summary = summary

        self._display_summary(summary)
        self._suite_running = False
        self._set_controls_state(True)

    def _on_suite_error(self, error_text: str) -> None:
        self.log(f"[ERROR] Suite execution failed: {error_text}", "RED")
        self._suite_running = False
        self._set_controls_state(True)

    def _set_controls_state(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        self.btn_gen_keys.config(state=state)
        self.btn_run_attack.config(state=state)
        self.btn_prevention.config(state=state)
        self.btn_graphs.config(state=state)

    def _display_summary(self, summary: ExperimentSummary) -> None:
        if summary.results:
            latest = summary.results[-1]
            self.var_hash_legit.set(latest.legitimate_hash)
            self.var_hash_malic.set(latest.malicious_hash)

        self.log("------------------------------------------------------", "INFO")
        self.log(f"Mode: {summary.mode}", "INFO")
        self.log(f"Total tests: {summary.total_tests}", "INFO")
        self.log(f"Successful forgeries: {summary.successful_forgeries}", "INFO")

        rate_tag = "RED" if summary.success_rate > 0 else "GREEN"
        self.log(f"Forgery Success Rate: {summary.success_rate:.1f}%", rate_tag)
        self.log(f"Integrity Rate: {summary.integrity_rate:.1f}%", "GREEN")
        self.log(f"Authentication Rate: {summary.authentication_rate:.1f}%", "GREEN")
        self.log("======================================================", "INFO")

    def apply_prevention(self) -> None:
        self.current_mode = "SHA-256"
        self.var_mode.set("Current Mode: SHA-256 (Secure)")
        self.log("[SECURE] Prevention applied: SHA-256 is now enforced for all signatures.", "GREEN")
        self.log("[SECURE] Launching SHA-256 validation suite now...", "GREEN")

        if self.public_key is None:
            self.log("[SYSTEM] Generate keys first, then apply prevention again to run tests.", "HIGHLIGHT")
            return

        if self._suite_running:
            self.log("[SYSTEM] Please wait. A test suite is already running...", "HIGHLIGHT")
            return

        self.log("", "INFO")
        self.log("================ PREVENTION VALIDATION ================", "INFO")
        self.log("[SECURE] Running 25 automated SHA-256 prevention test cases...", "GREEN")

        self._suite_running = True
        self._set_controls_state(False)
        threading.Thread(target=self._run_suite_worker, args=("SHA-256",), daemon=True).start()

    def show_graphs(self) -> None:
        if self._suite_running:
            self.log("[SYSTEM] Please wait. A test suite is already running...", "HIGHLIGHT")
            return

        self.log("[SYSTEM] Generating mandatory comparative graphs...", "INFO")

        if self.last_md5_summary is None:
            self.log("[SYSTEM] No MD5 suite found. Running MD5 suite first...", "INFO")
            self.last_md5_summary = run_forgery_suite(
                mode="MD5",
                total_tests=25,
                case_callback=self._log_case_progress,
            )
            self.log("[SYSTEM] MD5 suite for graph preparation completed.", "INFO")
        if self.last_sha_summary is None:
            self.log("[SYSTEM] No SHA-256 suite found. Running SHA-256 suite first...", "INFO")
            self.last_sha_summary = run_forgery_suite(
                mode="SHA-256",
                total_tests=25,
                case_callback=self._log_case_progress,
            )
            self.log("[SYSTEM] SHA-256 suite for graph preparation completed.", "INFO")

        graph_path = plot_all_graphs(self.last_md5_summary, self.last_sha_summary)
        self.log(f"[SYSTEM] Graph generated: {graph_path}", "GREEN")


if __name__ == "__main__":
    app_root = tk.Tk()
    app = PGPAttackGUI(app_root)
    app_root.mainloop()
