"""
Cryptopals Set 1, Challenge 6; Break repeating-key XOR

The given file in base64 has been encrypted with
repeating-key XOR. Decrypt it.
"""
import base64
from utils import hamming, break_repeating_xor

# Given test case
test1 = b"this is a test"
test2 = b"wokka wokka!!!"
# Hamming distance should be 37
print(f"Hamming test returns: {hamming(test1, test2)}")

with open("Challenge6.txt", "r") as ciphertext_b64:
    ciphertext = base64.b64decode(ciphertext_b64.read())

plaintext, key = break_repeating_xor(ciphertext)
plaintext_str = plaintext.decode("ascii")

print(f"The key is: {key}")
print(f"The plaintext is:\n{plaintext_str}")
