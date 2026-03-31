import tkinter as tk
from tkinter import scrolledtext
import hashlib
import random
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import statistics
import random

TOTAL_TESTS = 25

class PGPSimulator:
    def __init__(self):
        self.mode = "MD5"  
        self.success_results = []
        self.hash_times = []
        self.sign_times = []

    def generate_key(self):
        return "KEY_" + str(random.randint(10000, 99999))

    def hash_data(self, data):
        start = time.perf_counter()

        if self.mode == "MD5":
            digest = hashlib.md5(data.encode()).hexdigest()
        else:
            digest = hashlib.sha256(data.encode()).hexdigest()

        end = time.perf_counter()
        self.hash_times.append(end - start)

        return digest
    
    def generate_rsa_keys(self):
        p = 61
        q = 53
        n = p * q
        phi = (p-1)*(q-1)
        e = 17

        d = pow(e, -1, phi)
        self.public_key = (e, n)
        self.private_key = (d, n)


    def sign(self, hash_value):
        d, n = self.private_key
        hash_int = int(hash_value, 16)
        signature = pow(hash_int, d, n)
        return signature
    
    def verify(self, hash_value, signature):
        e, n = self.public_key
        decrypted_hash = pow(signature, e, n)
        return decrypted_hash == int(hash_value, 16) % n

    # Simulate collision attack
    def collision_attack(self, original_hash):
        if self.mode == "MD5":
            return original_hash  
        else:
            fake_key = self.generate_key()
            return self.hash_data(fake_key)

    def run_tests(self, log):
        self.generate_rsa_keys()   # generate RSA keys once

        results = []
        hash_times = []
        sign_times = []

        for i in range(TOTAL_TESTS):

            key = self.generate_key()

            # HASHING
            start_hash = time.perf_counter()

            if self.mode == "MD5":
                hashed = hashlib.md5(key.encode()).hexdigest()
            else:
                hashed = hashlib.sha256(key.encode()).hexdigest()

            end_hash = time.perf_counter()
            hash_times.append(end_hash - start_hash)

            # RSA SIGNING
            start_sign = time.perf_counter()
            signature = self.sign(hashed)
            end_sign = time.perf_counter()
            sign_times.append(end_sign - start_sign)

            # Collision simulation
            if self.mode == "MD5":
                if (random.random() > 0.25):
                    forged_hash = hashed
                else:
                    forged_hash = hashed[0:-2] + "f"
            else:
                fake_key = self.generate_key()
                forged_hash = hashlib.sha256(fake_key.encode()).hexdigest()

            valid = self.verify(forged_hash, signature)

            if valid:
                results.append(1)
                log.insert(tk.END, f"[Test {i+1}] Forgery SUCCESS\n", "red")
            else:
                results.append(0)
                log.insert(tk.END, f"[Test {i+1}] Forgery Failed\n", "green")

        if self.mode == "MD5":
            self.md5_results = results
            self.md5_hash_time = sum(hash_times)/len(hash_times)
            self.md5_sign_time = sum(sign_times)/len(sign_times)
        else:
            self.sha_results = results
            self.sha_hash_time = sum(hash_times)/len(hash_times)
            self.sha_sign_time = sum(sign_times)/len(sign_times)


    def success_rate(self):
        return sum(self.success_results) / len(self.success_results)

    def integrity_rate(self):
        return 1 - self.success_rate()

    def avg_hash_time(self):
        return statistics.mean(self.hash_times)

    def avg_sign_time(self):
        return statistics.mean(self.sign_times)


# ---------------- GUI ---------------- #

sim = PGPSimulator()

root = tk.Tk()
root.title("PGP Weak Hash Collision Simulation")
root.geometry("1000x500")

log_area = scrolledtext.ScrolledText(root, width=90, height=20)
log_area.pack(pady=10)

log_area.tag_config("red", foreground="red")
log_area.tag_config("green", foreground="green")

def generate_keys():
    log_area.insert(tk.END, "[Keys Generated]\n\n")

def run_attack():
    log_area.insert(tk.END, f"Running Attack in {sim.mode} Mode...\n\n")
    sim.run_tests(log_area)

def apply_prevention():
    sim.mode = "SHA256"
    log_area.insert(tk.END, "\nSwitched to SHA-256 Secure Mode.\n\n")

def show_graphs():

    if not hasattr(sim, "md5_results") or not hasattr(sim, "sha_results"):
        print("Run both MD5 and SHA-256 attacks first!")
        return

    fig = plt.figure(figsize=(12, 8))

    # Forgery Success Rate Comparison
    plt.subplot(2,2,1)
    plt.plot(sim.md5_results, label="MD5 (Weak)")
    plt.plot(sim.sha_results, label="SHA-256 (Secure)")
    plt.title("Forgery Success Rate Comparison")
    plt.xlabel("Test Case")
    plt.ylabel("Success (1/0)")
    plt.legend()

    # Time vs Hash Size Comparison
    plt.subplot(2,2,2)
    plt.bar(["MD5 (128 bit)", "SHA-256 (256 bit)"],
            [sim.md5_hash_time, sim.sha_hash_time])
    plt.title("Average Hash Time Comparison")

    # Integrity Rate Comparison
    plt.subplot(2,2,3)
    md5_integrity = 1 - (sum(sim.md5_results)/len(sim.md5_results))
    sha_integrity = 1 - (sum(sim.sha_results)/len(sim.sha_results))

    plt.bar(["MD5", "SHA-256"], [md5_integrity, sha_integrity])
    plt.title("Integrity Rate Comparison")

    # Latency Overhead Comparison
    plt.subplot(2,2,4)
    plt.bar(["MD5 Sign", "SHA-256 Sign"],
            [sim.md5_sign_time, sim.sha_sign_time])
    plt.title("Signing Latency Overhead")

    plt.tight_layout()
    plt.show()


tk.Button(root, text="Generate Keys", command=generate_keys, width=20).pack()
tk.Button(root, text="Run Attack", command=run_attack, width=20).pack()
tk.Button(root, text="Apply Prevention (SHA-256)", command=apply_prevention, width=25).pack()
tk.Button(root, text="Show Graphs", command=show_graphs, width=20).pack()

root.mainloop()
