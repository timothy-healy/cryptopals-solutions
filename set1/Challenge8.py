"""
Cryptopals Set 1, Challenge 8; Detect AES in ECB mode

One hex-encoded ciphertext in the given file has been encrypted with ECB.
Detect it.
"""
import sys
sys.path.append("..")
from utils import detect_ecb

# collect all strings with ECB detected
# for this challenge, should be only 1
ecb_detected = []
with open ("Challenge8.txt", "r") as candidates:
    for line, candidate_hex in enumerate(candidates, 1):
        candidate_hex = candidate_hex.strip()
        candidate = bytes.fromhex(candidate_hex)

        if detect_ecb(candidate)[0]:
            ecb_detected.append((line, candidate))

for line, ciphertext in ecb_detected:
    print(f"ECB detected in number {line}")
    print(f"The ciphertext is: {ciphertext.hex()}")
