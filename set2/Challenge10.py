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

KEY = b"YELLOW SUBMARINE"
BLOCK_SIZE = len(KEY)
IV = b"\x00" * BLOCK_SIZE

### Given Test File ###
with open("Challenge10.txt", "r") as ciphertext_f_b64:
    ciphertext_b64 = ciphertext_f_b64.read()
    ciphertext = base64.b64decode(ciphertext_b64)

plaintext = decrypt_cbc(ciphertext, KEY, IV, BLOCK_SIZE)

print("Given test file:")
print(plaintext.decode("ascii"))

### Other Tests ###
print("Meow test:")
plaintext = b"MEOW MEOW MEOW"
ciphertext = encrypt_cbc(plaintext, KEY, IV, BLOCK_SIZE)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, KEY, IV, BLOCK_SIZE)
print(decrypted)
assert plaintext == decrypted

## Already Full Block ##
print("\nFull block test:")
plaintext = b"YELLOW SUBMARINE"
ciphertext = encrypt_cbc(plaintext, KEY, IV, BLOCK_SIZE)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, KEY, IV, BLOCK_SIZE)
print(decrypted)
assert plaintext == decrypted

## Multiples Full Blocks ##
print("\nMultiple full blocks test:")
plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINE"
ciphertext = encrypt_cbc(plaintext, KEY, IV, BLOCK_SIZE)
print(ciphertext)
decrypted = decrypt_cbc(ciphertext, KEY, IV, BLOCK_SIZE)
print(decrypted)
assert plaintext == decrypted
