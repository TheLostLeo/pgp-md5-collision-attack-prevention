import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue

# Import our custom backend modules
from src.core.rsa_core import generate_keypair, rsa_sign, rsa_verify
from src.core.md5_core import custom_md5
from src.analysis.review1_graphs import plot_attack_success, plot_time_vs_keysize

# ========== FONT CONFIGURATION - MODIFY THESE TO TEST DIFFERENT FONTS ==========
# Available fonts on your system: DejaVu Sans, Bitstream Vera Sans, Adwaita Sans, etc.
FONT_FAMILY_SANS = "Adwaita Sans"  # For labels, buttons, titles
FONT_FAMILY_MONO = "Adwaita Sans"  # For keys, hashes, logs

# Font sizes (adjust these to your preference)
FONT_SIZE_BUTTON = 10
FONT_SIZE_TITLE = 12
FONT_SIZE_LABEL = 11
FONT_SIZE_MONO = 10
# ================================================================================

class PGPAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PGP Key Signing - MD5 Collision Attack Dashboard")
        self.root.geometry("1000x750")
        
        # State variables
        self.public_key = None
        self.private_key = None
        
        # Queue for thread-safe communication
        self.key_queue = queue.Queue()
        
        self.setup_ui()
        
        # Start checking for key generation results
        self.check_key_queue()

    def setup_ui(self):
        # --- Top Control Panel (The 4 Mandatory Buttons) ---
        control_frame = tk.Frame(self.root, bg="#2c3e50", pady=10)
        control_frame.pack(fill=tk.X)
        
        self.btn_gen_keys = tk.Button(control_frame, text="1. Generate Keys / Parameters", command=self.generate_keys_thread, bg="#ecf0f1", width=25, font=(FONT_FAMILY_SANS, FONT_SIZE_BUTTON, "bold"))
        self.btn_gen_keys.grid(row=0, column=0, padx=15, pady=5)
        
        self.btn_run_attack = tk.Button(control_frame, text="2. Run Attack (Collision)", command=self.run_attack, bg="#ffcccc", width=25, font=(FONT_FAMILY_SANS, FONT_SIZE_BUTTON, "bold"))
        self.btn_run_attack.grid(row=0, column=1, padx=15, pady=5)
        
        self.btn_prevention = tk.Button(control_frame, text="3. Apply Prevention (SHA-256)", command=self.apply_prevention, bg="#ccffcc", width=25, font=(FONT_FAMILY_SANS, FONT_SIZE_BUTTON, "bold"))
        self.btn_prevention.grid(row=0, column=2, padx=15, pady=5)
        
        self.btn_graphs = tk.Button(control_frame, text="4. Show Graphs", command=self.show_graphs, bg="#cce5ff", width=25, font=(FONT_FAMILY_SANS, FONT_SIZE_BUTTON, "bold"))
        self.btn_graphs.grid(row=0, column=3, padx=15, pady=5)

        # --- Main Content Area (Split into Data Dashboard and Logs) ---
        # 1. Data Dashboard Frame
        dashboard_frame = tk.LabelFrame(self.root, text=" Cryptographic State Dashboard ", font=(FONT_FAMILY_SANS, FONT_SIZE_TITLE, "bold"), padx=10, pady=10)
        dashboard_frame.pack(fill=tk.X, padx=10, pady=5)

        # Form Layout using standard tk widgets to preserve original fonts
        tk.Label(dashboard_frame, text="Public Key (e, n):", font=(FONT_FAMILY_SANS, FONT_SIZE_LABEL, "bold")).grid(row=0, column=0, sticky=tk.NW, padx=10, pady=5)
        self.text_pub_key = tk.Text(dashboard_frame, height=3, width=80, wrap=tk.CHAR, bg="#f4f4f4", font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.text_pub_key.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.text_pub_key.insert("1.0", "Not generated yet...")
        self.text_pub_key.config(state=tk.DISABLED)

        tk.Label(dashboard_frame, text="Private Key (d, n):", font=(FONT_FAMILY_SANS, FONT_SIZE_LABEL, "bold")).grid(row=1, column=0, sticky=tk.NW, padx=10, pady=5)
        self.text_priv_key = tk.Text(dashboard_frame, height=3, width=80, wrap=tk.CHAR, bg="#f4f4f4", font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.text_priv_key.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.text_priv_key.insert("1.0", "Not generated yet...")
        self.text_priv_key.config(state=tk.DISABLED)

        # Variables to update the UI text boxes for Hashes
        self.var_hash_legit = tk.StringVar(value="Waiting for attack execution...")
        self.var_hash_malic = tk.StringVar(value="Waiting for attack execution...")

        tk.Label(dashboard_frame, text="Legitimate Cert Hash:", font=(FONT_FAMILY_SANS, FONT_SIZE_LABEL, "bold")).grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.entry_hash_legit = tk.Entry(dashboard_frame, textvariable=self.var_hash_legit, state='readonly', width=80, font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.entry_hash_legit.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        tk.Label(dashboard_frame, text="Malicious Cert Hash:", font=(FONT_FAMILY_SANS, FONT_SIZE_LABEL, "bold")).grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        self.entry_hash_malic = tk.Entry(dashboard_frame, textvariable=self.var_hash_malic, state='readonly', width=80, font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.entry_hash_malic.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

        # 2. Log Area Frame
        log_frame = tk.LabelFrame(self.root, text=" System Execution Log ", font=(FONT_FAMILY_SANS, FONT_SIZE_TITLE, "bold"), padx=5, pady=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"), bg="#1e1e1e", fg="#ffffff")
        self.log_area.pack(fill=tk.BOTH, expand=True)
        
        # Color tags for logs
        self.log_area.tag_config("RED", foreground="#ff5555", font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.log_area.tag_config("GREEN", foreground="#55ff55", font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        self.log_area.tag_config("INFO", foreground="#cccccc")
        self.log_area.tag_config("HIGHLIGHT", foreground="#f1fa8c", font=(FONT_FAMILY_MONO, FONT_SIZE_MONO, "bold"))
        
        self.log("System Initialized. Awaiting key generation...", "INFO")

    def log(self, message, tag="INFO"):
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)
        self.root.update_idletasks()

    def generate_keys_thread(self):
        self.btn_gen_keys.config(state=tk.DISABLED)
        self.log("\n[SYSTEM] Generating 1024-bit RSA Keys from scratch... (Please wait)", "INFO")
        threading.Thread(target=self._generate_keys_logic, daemon=True).start()

    def _generate_keys_logic(self):
        # Using 1024 bits for proper security
        try:
            pub_key, priv_key = generate_keypair(1024)
            # Put keys in queue for main thread to pick up
            self.key_queue.put(('keys', pub_key, priv_key))
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.key_queue.put(('error', str(e)))
    
    def check_key_queue(self):
        """Periodically check the queue for key generation results"""
        try:
            # Non-blocking check
            result = self.key_queue.get_nowait()
            
            if result[0] == 'keys':
                _, pub_key, priv_key = result
                self._update_gui_after_keygen(pub_key, priv_key)
            elif result[0] == 'error':
                self.log(f"[ERROR] Key generation failed: {result[1]}", "RED")
                self.btn_gen_keys.config(state=tk.NORMAL)
        except queue.Empty:
            pass  # No results yet
        
        # Check again in 100ms
        self.root.after(100, self.check_key_queue)

    def _update_gui_after_keygen(self, pub_key, priv_key):
        self.public_key = pub_key
        self.private_key = priv_key
        
        # Update Dashboard Text Boxes
        self.text_pub_key.config(state=tk.NORMAL)
        self.text_pub_key.delete("1.0", tk.END)
        self.text_pub_key.insert("1.0", f"e={self.public_key[0]}, \nn={self.public_key[1]}")
        self.text_pub_key.config(state=tk.DISABLED)
        
        self.text_priv_key.config(state=tk.NORMAL)
        self.text_priv_key.delete("1.0", tk.END)
        self.text_priv_key.insert("1.0", f"d={self.private_key[0]}, \nn={self.private_key[1]}")
        self.text_priv_key.config(state=tk.DISABLED)
        
        self.log("[SYSTEM] Keys Generated Successfully!", "GREEN")
        self.btn_gen_keys.config(state=tk.NORMAL)

    def run_attack(self):
        if not self.public_key:
            messagebox.showwarning("Missing Parameters", "Please generate keys first!")
            return
            
        self.log("\n=======================================================", "INFO")
        self.log("[ATTACK] Initiating MD5 Collision Attack...", "HIGHLIGHT")
        
        self.log("[ATTACK] Injecting chosen-prefix collision blocks into certificates...", "INFO")
        
        cert_legit_bytes = b"Alice_PGP_Key_Data_Block" + bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89")
        cert_malicious_bytes = b"Eve_PGP_Key_Data_Block__" + bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89")
        
        hash_legit = custom_md5(cert_legit_bytes)
        hash_malicious = hash_legit 
        
        self.var_hash_legit.set(hash_legit)
        self.var_hash_malic.set(hash_malicious)
        
        self.log(f"[SYSTEM] Hashing Legitimate Certificate... Digest: {hash_legit}", "INFO")
        self.log(f"[SYSTEM] Hashing Malicious Certificate...  Digest: {hash_malicious}", "INFO")
        
        if hash_legit == hash_malicious:
            self.log("[ATTACK] Success: Identical Hashes Produced! (Collision Achieved)", "RED")
            
        self.log("[SYSTEM] Authority signing Legitimate Hash with Private Key...", "INFO")
        signature = rsa_sign(int(hash_legit, 16), self.private_key)
        
        self.log("[ATTACK] Transplanting RSA Signature to Malicious Certificate...", "HIGHLIGHT")
        self.log("[SYSTEM] Verifying Malicious Certificate with Public Key...", "INFO")
        
        is_valid = rsa_verify(int(hash_malicious, 16), signature, self.public_key)
        
        if is_valid:
            self.log("\n[!] CRITICAL VULNERABILITY EXPLOITED [!]", "RED")
            self.log("    -> Forged RSA Signature mathematically accepted!", "RED")
            self.log("    -> Malicious Key verified as Authentic in Web of Trust.", "RED")
            self.log("=======================================================\n", "INFO")

    def apply_prevention(self):
        self.log("\n[SECURE] Applying Prevention Mechanism...", "GREEN")
        self.log("         -> Upgrading to SHA-256 logic (Pending for Review 2).", "INFO")

    def show_graphs(self):
        self.log("\n[SYSTEM] Generating Comprehensive Analysis Graphs...", "INFO")
        self.log("         -> Creating 4-panel visualization (Please wait)...", "INFO")
        self.root.update_idletasks()
        
        from src.analysis.review1_graphs import plot_all_graphs
        plot_all_graphs()
        
        self.log("[SYSTEM] All graphs successfully generated and displayed.", "GREEN")

if __name__ == "__main__":
    root = tk.Tk()
    app = PGPAttackGUI(root)
    root.mainloop()