# rsa_core.py
import random

def is_prime(n, k=3):
    """Miller-Rabin primality test (optimized with k=3 for faster generation)."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for p in small_primes:
        if n % p == 0:
            return n == p

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=512):
    """Generates a prime number of the specified bit length."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(e, phi):
    """Computes the modular inverse to find the private key 'd'."""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

def generate_keypair(bits=1024):
    """Generates RSA public and private keys."""
    print("Generating key pair")
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537 
    d = mod_inverse(e, phi)
    
    print("Generated key pair\n")
    return ((e, n), (d, n))

def rsa_sign(message_hash_int, private_key):
    """Signs the integer representation of the hash using pow()"""
    d, n = private_key
    return pow(message_hash_int, d, n)

def rsa_verify(message_hash_int, signature, public_key):
    """Verifies the signature matches the hash using pow()"""
    e, n = public_key
    decrypted_hash = pow(signature, e, n)
    return decrypted_hash == message_hash_int

def main():
    pub_key, priv_key = generate_keypair(1024)
    print("Public Key:", pub_key)
    print("Private Key:", priv_key)

if __name__ == "__main__":
    main()