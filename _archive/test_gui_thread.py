import tkinter as tk
from tkinter import scrolledtext
import threading
from rsa_core import generate_keypair

class TestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Test Key Generation")
        
        self.btn = tk.Button(root, text="Generate Keys", command=self.generate_keys)
        self.btn.pack(pady=10)
        
        self.log = scrolledtext.ScrolledText(root, width=80, height=20)
        self.log.pack(padx=10, pady=10)
        
        self.text_result = tk.Text(root, height=5, width=80)
        self.text_result.pack(padx=10, pady=10)
        
    def log_msg(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        print(msg)  # Also print to console
        
    def generate_keys(self):
        self.btn.config(state=tk.DISABLED)
        self.log_msg("Starting key generation in thread...")
        threading.Thread(target=self._gen_logic, daemon=True).start()
        
    def _gen_logic(self):
        self.log_msg("Thread started, generating 1024-bit keys...")
        try:
            pub, priv = generate_keypair(1024)
            self.log_msg(f"Keys generated! Public key e={pub[0]}")
            self.root.after(0, self._update_gui, pub, priv)
        except Exception as e:
            self.log_msg(f"ERROR: {e}")
            import traceback
            self.log_msg(traceback.format_exc())
            
    def _update_gui(self, pub, priv):
        self.log_msg("Updating GUI with keys...")
        self.text_result.delete("1.0", tk.END)
        self.text_result.insert("1.0", f"Public: e={pub[0]}, n={pub[1]}\n")
        self.text_result.insert(tk.END, f"Private: d={priv[0]}, n={priv[1]}")
        self.btn.config(state=tk.NORMAL)
        self.log_msg("DONE!")

if __name__ == "__main__":
    root = tk.Tk()
    app = TestGUI(root)
    root.mainloop()
