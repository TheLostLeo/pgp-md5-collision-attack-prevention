message = 12345
e = 65537
n = 999630013489
d = 611157
encrypted = pow(message, e, n)
decrypted = pow(encrypted, d, n)
print(message == decrypted)