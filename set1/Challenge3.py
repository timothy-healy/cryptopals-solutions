"""
Cryptopals Set 1, Challenge 3; Breaking a single character XOR cipher

The hex encoded string:
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
has been XOR'd against a single character. Find the key, decrypt the message.
"""
import sys

sys.path.append("..")
from utils import break_single_xor
    
ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
ciphertext = bytes.fromhex(ciphertext_hex)

plaintext, key = break_single_xor(ciphertext)
plaintext_str = plaintext.decode("ascii")

print(plaintext_str)
