from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
from tkinter import ttk
from PIL import Image, ImageTk

from src.analysis.graphs import export_graph_package
from src.attack.experiment_engine import (
    ExperimentSummary,
    SECURE_PREVENTION_MODES,
    TestCaseResult,
    run_forgery_suite,
)
from src.core.rsa_core import generate_keypair


class PGPAttackGUI:
    def __init__(self, root: tk.Tk):
        self.total_tests = 25
        self.root = root
        self.root.title("PGP Key Signing: MD5 Collision Forgery vs SHA-256 Prevention")
        self.root.geometry("1120x760")

        self.current_mode = "MD5"
        self.prevention_summaries: dict[str, ExperimentSummary] = {}
        self.public_key = None
        self.private_key = None
        self.last_md5_summary: ExperimentSummary | None = None
        self.last_sha_summary: ExperimentSummary | None = None

        self.var_pub_key = tk.StringVar(value="Not generated yet...")
        self.var_priv_key = tk.StringVar(value="Not generated yet...")
        self.var_hash_legit = tk.StringVar(value="Run tests to view latest digest")
        self.var_hash_malic = tk.StringVar(value="Run tests to view latest digest")
        self.var_mode = tk.StringVar(value="Current Mode: MD5 (Vulnerable)")
        self.var_prevention_method = tk.StringVar(value="SHA-256")
        self._suite_running = False
        self.graph_window: tk.Toplevel | None = None
        self.graph_view_var = tk.StringVar(value="")
        self.graph_paths: dict[str, str] = {}
        self.graph_image_label: tk.Label | None = None
        self.graph_image_ref = None

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

        tk.Label(
            top,
            text="Prevention Method:",
            bg="#1e2a38",
            fg="#e5e7eb",
            font=("Arial", 10, "bold"),
        ).grid(row=1, column=1, sticky="e", padx=8, pady=(4, 2))

        self.prevention_combo = ttk.Combobox(
            top,
            textvariable=self.var_prevention_method,
            values=list(SECURE_PREVENTION_MODES),
            state="readonly",
            width=18,
        )
        self.prevention_combo.grid(row=1, column=2, sticky="w", padx=8, pady=(4, 2))

        self.btn_switch_md5 = tk.Button(
            top,
            text="Switch To MD5 Mode",
            command=self.switch_to_md5_mode,
            bg="#ffe6cc",
            width=20,
            font=("Arial", 9, "bold"),
        )
        self.btn_switch_md5.grid(row=1, column=3, sticky="w", padx=8, pady=(4, 2))

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

        mode = self.current_mode
        if mode == "MD5":
            self.log(f"[ATTACK] Running {self.total_tests} automated MD5 collision-forgery test cases...", "HIGHLIGHT")
        else:
            self.log(f"[SECURE] Running {self.total_tests} automated {mode} prevention test cases...", "GREEN")

        self._suite_running = True
        self._set_controls_state(False)
        threading.Thread(target=self._run_suite_worker, args=(mode,), daemon=True).start()

    def _run_suite_worker(self, mode: str) -> None:
        try:
            def progress(case_result: TestCaseResult) -> None:
                self.root.after(0, self._log_case_progress, case_result)

            summary = run_forgery_suite(mode=mode, total_tests=self.total_tests, case_callback=progress)
            self.root.after(0, self._on_suite_complete, summary)
        except Exception as exc:
            self.root.after(0, self._on_suite_error, str(exc))

    def _log_case_progress(self, result: TestCaseResult) -> None:
        color = "RED" if result.signature_valid else "GREEN"
        status = "FORGERY ACCEPTED" if result.signature_valid else "FORGERY BLOCKED"
        self.log(
            f"Case {result.case_id:02d}/{self.total_tests} | {result.key_label} | {status} | {result.note}",
            color,
        )

    def _on_suite_complete(self, summary: ExperimentSummary) -> None:
        if summary.mode == "MD5":
            self.last_md5_summary = summary
        else:
            self.prevention_summaries[summary.mode] = summary
            if summary.mode == "SHA-256":
                self.last_sha_summary = summary

        self._display_summary(summary)
        self._suite_running = False
        self._set_controls_state(True)
        self.log("[SYSTEM] Suite completed. You can run attack again or switch modes.", "INFO")

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
        self.btn_switch_md5.config(state=state)
        self.prevention_combo.config(state="readonly" if enabled else "disabled")

    def switch_to_md5_mode(self) -> None:
        if self._suite_running:
            self.log("[SYSTEM] Please wait. Current suite is still running...", "HIGHLIGHT")
            return
        self.current_mode = "MD5"
        self.var_mode.set("Current Mode: MD5 (Vulnerable)")
        self.log("[SYSTEM] Switched back to MD5 mode. You can run attack again.", "HIGHLIGHT")

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
        selected_method = self.var_prevention_method.get().strip().upper()
        self.current_mode = selected_method
        self.var_mode.set(f"Current Mode: {selected_method} (Secure)")
        self.log(f"[SECURE] Prevention applied: {selected_method} is now enforced for all signatures.", "GREEN")
        self.log(f"[SECURE] Launching {selected_method} validation suite now...", "GREEN")

        if self.public_key is None:
            self.log("[SYSTEM] Generate keys first, then apply prevention again to run tests.", "HIGHLIGHT")
            return

        if self._suite_running:
            self.log("[SYSTEM] Please wait. A test suite is already running...", "HIGHLIGHT")
            return

        self.log("", "INFO")
        self.log("================ PREVENTION VALIDATION ================", "INFO")
        self.log(f"[SECURE] Running {self.total_tests} automated {selected_method} prevention test cases...", "GREEN")

        self._suite_running = True
        self._set_controls_state(False)
        threading.Thread(target=self._run_suite_worker, args=(selected_method,), daemon=True).start()

    def show_graphs(self) -> None:
        if self._suite_running:
            self.log("[SYSTEM] Please wait. A test suite is already running...", "HIGHLIGHT")
            return

        self.log("[SYSTEM] Generating mandatory comparative graphs...", "INFO")

        if self.last_md5_summary is None:
            self.log("[SYSTEM] No MD5 suite found. Running MD5 suite first...", "INFO")
            self.last_md5_summary = run_forgery_suite(
                mode="MD5",
                total_tests=self.total_tests,
                case_callback=self._log_case_progress,
            )
            self.log("[SYSTEM] MD5 suite for graph preparation completed.", "INFO")
        if self.last_sha_summary is None:
            self.log("[SYSTEM] No SHA-256 suite found. Running SHA-256 suite first...", "INFO")
            self.last_sha_summary = run_forgery_suite(
                mode="SHA-256",
                total_tests=self.total_tests,
                case_callback=self._log_case_progress,
            )
            self.log("[SYSTEM] SHA-256 suite for graph preparation completed.", "INFO")

        generated = export_graph_package(self.last_md5_summary, self.last_sha_summary)

        self.log("[SYSTEM] Project Required Graphs Generated:", "GREEN")
        self.log(f"  1) {generated['mandatory_1_success_rate']}", "GREEN")
        self.log(f"  2) {generated['mandatory_2_time_vs_key_size']}", "GREEN")
        self.log(f"  3) {generated['mandatory_3_cia_rates']}", "GREEN")
        self.log(f"  4) {generated['mandatory_4_latency_overhead']}", "GREEN")
        self.log(f"  Combined Dashboard: {generated['mandatory_dashboard_4in1']}", "GREEN")
        self._open_graph_viewer(generated)

    def _open_graph_viewer(self, generated: dict[str, str]) -> None:
        self.graph_paths = dict(generated)

        if self.graph_window is None or not self.graph_window.winfo_exists():
            self.graph_window = tk.Toplevel(self.root)
            self.graph_window.title("Generated Graph Viewer")
            self.graph_window.geometry("1200x820")

            control_frame = tk.Frame(self.graph_window, pady=8)
            control_frame.pack(fill=tk.X)

            tk.Label(control_frame, text="Select Graph:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=8)
            graph_selector = ttk.Combobox(
                control_frame,
                textvariable=self.graph_view_var,
                state="readonly",
                width=55,
            )
            graph_selector.pack(side=tk.LEFT, padx=8)
            graph_selector.bind("<<ComboboxSelected>>", lambda _: self._display_selected_graph())
            self._graph_selector = graph_selector

            self.graph_image_label = tk.Label(self.graph_window, bg="#111827")
            self.graph_image_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        else:
            self.graph_window.deiconify()
            self.graph_window.lift()

        graph_names = list(self.graph_paths.keys())
        self._graph_selector["values"] = graph_names

        preferred_default = "mandatory_dashboard_4in1"
        if preferred_default in graph_names:
            self.graph_view_var.set(preferred_default)
        elif graph_names:
            self.graph_view_var.set(graph_names[0])

        self._display_selected_graph()

    def _display_selected_graph(self) -> None:
        if self.graph_image_label is None:
            return

        selected = self.graph_view_var.get()
        image_path = self.graph_paths.get(selected)
        if not image_path:
            return

        try:
            image = Image.open(image_path)
            image.thumbnail((1150, 760), Image.Resampling.LANCZOS)
            self.graph_image_ref = ImageTk.PhotoImage(image)
            self.graph_image_label.config(image=self.graph_image_ref)
        except Exception as exc:
            self.log(f"[ERROR] Failed to render graph image: {exc}", "RED")


if __name__ == "__main__":
    app_root = tk.Tk()
    app = PGPAttackGUI(app_root)
    app_root.mainloop()
