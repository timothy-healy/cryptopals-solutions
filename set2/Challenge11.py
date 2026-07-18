"""
Cryptopals Set 2, Challenge 11; ECB/CBC detection oracle.

Write a function that randomly encrypts plaintext in either ECB or CBC mode.
The key used is randomly generated and unknown.
Detect the block cipher mode the function is using each time.
"""
import sys
sys.path.append("..")
from utils import random_encrypt_aes, detect_ecb_cbc


### Attack ###
# Using 43 of the same byte consecutively guarantees second and third block are identical
# Even after the random prepending/appending
# Allows for ECB to be easily detected
chosen_plaintext = b"a" * 43
ciphertext, actual_mode = random_encrypt_aes(chosen_plaintext)
detected = detect_ecb_cbc(ciphertext)
print(f"Detected: {detected}")
assert detected == actual_mode
print("Correct")

### More Checks ###
# Do many tests to ensure not getting lucky
print("\n10,000 tests:")
for i in range(10000):
    ciphertext, actual_mode = random_encrypt_aes(chosen_plaintext)
    detected = detect_ecb_cbc(ciphertext)
    assert detected == actual_mode, f"Failed on iteration {i}"
print("Done")
