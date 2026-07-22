"""
Cryptopals Set 2, Challenge 11; ECB/CBC detection oracle.

Write a function that randomly encrypts plaintext in either ECB or CBC mode.
The key used is randomly generated and unknown.
Detect the block cipher mode the function is using each time.
"""
import random
import secrets
from Crypto.Cipher import AES
import sys
sys.path.append("..")
from utils import gen_rand_key, pkcs7_pad, encrypt_cbc, detect_ecb

def random_encrypt_aes(plaintext):
    """
    Randomly encrypts the given plaintext in either ECB or CBC mode
    after randomly prepending and appending the plaintext with bytes.
    For the purpose of checking if detection is done properly (Challenge 11),
    this returns the mode used.

    Args:
        plaintext: Plaintext to encrypt as bytes.

    Returns:
        tuple:
            - bytes: Resulting ciphertext.
            - str: Mode used to encrypt.
    """
    key = gen_rand_key()
    prefix_length = random.randint(5, 10)
    postfix_length = random.randint(5, 10)

    prefix = bytes([random.randint(0,255) for i in range(prefix_length)])
    postfix = bytes([random.randint(0,255) for i in range(postfix_length)])

    appended_plaintext = prefix + plaintext + postfix

    mode = random.randint(0,1)

    if mode == 0:
        mode = "ECB"
        aes_cipher = AES.new(key, AES.MODE_ECB)
        # pad plaintext before encrypting
        appended_plaintext = pkcs7_pad(appended_plaintext)
        ciphertext = aes_cipher.encrypt(appended_plaintext)
    else:
        mode = "CBC"
        # random IV each time
        iv = secrets.token_bytes(16)
        ciphertext = encrypt_cbc(appended_plaintext, key, iv)

    return ciphertext, mode

def detect_ecb_cbc(ciphertext):
    """
    Detects whether the given ciphertext was encrypted in
    ECB or CBC mode.

    Args:
        ciphertext: Ciphertext as bytes.

    Returns:
        str: "ECB" if ECB mode detected, "CBC" otherwise.
    """
    if detect_ecb(ciphertext)[0]:
        return "ECB"
    else:
        return "CBC"

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
