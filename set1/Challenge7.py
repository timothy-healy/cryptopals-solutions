"""
Cryptopals Set 1, Challenge 7; Decrypt AES in ECB mode

The base64 text in the given file has been encrypted by
AES-128 in ECB mode under the key:
YELLOW SUBMARINE
Decrypt it.
"""
import base64
from Crypto.Cipher import AES

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)

with open("Challenge7.txt", "r") as ciphertext_b64:
    ciphertext = base64.b64decode(ciphertext_b64.read())

plaintext = cipher.decrypt(ciphertext)
plaintext_str = plaintext.decode("ascii")

print(plaintext_str)
