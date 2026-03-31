# attack_simulation.py
from rsa_core import generate_keypair, rsa_sign, rsa_verify
from md5_core import custom_md5

def run_partial_attack():
    print("--- 1. Generating Keys ---")
    public_key, private_key = generate_keypair(1024)
    print(f"Public Key (e, n) generated.")
    
    print("\n--- 2. Setting Up Hard-coded Collision Payloads ---")
    cert_legitimate_hex = (
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    
    cert_malicious_hex = (
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    
    cert_legitimate_bytes = bytes.fromhex(cert_legitimate_hex)
    cert_malicious_bytes = bytes.fromhex(cert_malicious_hex)
    
    print("\n--- 3. Hashing Payloads (MD5 From Scratch) ---")
    hash_legitimate = custom_md5(cert_legitimate_bytes)
    hash_malicious = custom_md5(cert_malicious_bytes)
    
    print(f"Hash of Legitimate Cert: {hash_legitimate}")
    print(f"Hash of Malicious Cert:  {hash_malicious}")
    
    if hash_legitimate == hash_malicious:
        print("--> COLLISION SUCCESSFUL: Both distinct payloads produced identical hashes!")
    
    print("\n--- 4. Trusted Authority Signs the Legitimate Certificate ---")
    # Convert hex hash to integer for RSA math
    hash_int = int(hash_legitimate, 16)
    signature = rsa_sign(hash_int, private_key)
    print("Authority has signed the Legitimate Hash.")
    
    print("\n--- 5. The Attack: Signature Transplantation ---")
    print("Attacker copies the signature and attaches it to the Malicious Certificate.")
    
    print("\n--- 6. Victim Verifies the Malicious Certificate ---")
    # Victim hashes the malicious cert, converts to int, and checks signature
    victim_hash_int = int(hash_malicious, 16)
    is_valid = rsa_verify(victim_hash_int, signature, public_key)
    
    if is_valid:
        print("--> CRITICAL VULNERABILITY: Forgery Accepted! Malicious Key Verified by System.")

if __name__ == "__main__":
    run_partial_attack()