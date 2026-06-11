"""
Cryptopals Set 2, Challenge 10; Implement CBC mode.

In CBC mode encryption, each plaintext block is XORed with the previous ciphertext block
before ECB mode encryption is applied.
The first is XORed with the initialization vector.
"""
import base64
import sys
sys.path.append("..")
from utils import encrypt_cbc, decrypt_cbc

key = b"YELLOW SUBMARINE"
block_size = len(key)
iv = b"\x00" * block_size

# given test file
with open("Challenge10.txt", "r") as ciphertext_f_b64:
    ciphertext_b64 = ciphertext_f_b64.read()
    ciphertext = base64.b64decode(ciphertext_b64)

plaintext = decrypt_cbc(ciphertext, key, iv, block_size)

print("Given test file:")
print(plaintext.decode("ascii"))

# my own test to verify encryption/decryption
# padding should be only difference
print("Meow test:")
plaintext = b"MEOW MEOW MEOW"
ciphertext = encrypt_cbc(plaintext, key, iv, block_size)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, key, iv, block_size)
print(decrypted)

# test an already full block
print("\nFull block test:")
plaintext = b"YELLOW SUBMARINE"
ciphertext = encrypt_cbc(plaintext, key, iv, block_size)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, key, iv, block_size)
print(decrypted)

# test multiple full blocks
print("\nMultiple full blocks test:")
plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINE"
ciphertext = encrypt_cbc(plaintext, key, iv, block_size)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, key, iv, block_size)
print(decrypted)
