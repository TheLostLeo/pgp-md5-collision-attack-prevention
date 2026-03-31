# md5_core.py
import struct
import math

def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

def custom_md5(message_bytes):
    
    # 1. Padding
    original_len_bits = (len(message_bytes) * 8) & 0xFFFFFFFFFFFFFFFF
    message_bytes += b'\x80' 
    
    while len(message_bytes) % 64 != 56:
        message_bytes += b'\x00'
        
    # Append 64-bit length
    message_bytes += struct.pack('<Q', original_len_bits) 
    
    # 2. Initialization Vectors
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    
    # Precompute sine constants T[i]
    T = [int(4294967296 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
    
    # Shift amounts for the 4 rounds
    S = [7, 12, 17, 22] * 4 + [5,  9, 14, 20] * 4 + \
        [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

    # 3. Process in 512-bit (64-byte) chunks
    for chunk_offset in range(0, len(message_bytes), 64):
        chunk = message_bytes[chunk_offset:chunk_offset+64]
        X = list(struct.unpack('<16I', chunk))
        
        a, b, c, d = A, B, C, D
        
        for i in range(64):
            if 0 <= i <= 15:
                F = (b & c) | ((~b) & d)
                g = i
            elif 16 <= i <= 31:
                F = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                F = c ^ (b | (~d))
                g = (7 * i) % 16
            
            # The core equation: A = B + ((A + F(B,C,D) + X[i] + T[i]) <<< S)
            F = (F + a + T[i] + X[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + left_rotate(F, S[i])) & 0xFFFFFFFF
            
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
        
    return struct.pack('<4I', A, B, C, D).hex()