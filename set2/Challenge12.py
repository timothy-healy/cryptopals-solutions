"""
Cryptopals Set 2, Challenge 12; Byte-at-a-time ECB decryption (simple)

Create new oracle function that appends the given base 64 string to the plaintext then
encrypts under ECB mode using a consistent, unknown key.
Decrypt this given string using repeated calls to the oracle function.
"""
import random
from Crypto.Cipher import AES
import base64
import sys
sys.path.append("..")
from utils import detect_ecb, pkcs7_pad

RAND_KEY = bytes([random.randint(0, 255) for i in range(16)])
AES_CIPHER = AES.new(RAND_KEY, AES.MODE_ECB)
APPEND_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
APPEND_BYTES = base64.b64decode(APPEND_B64)


def ecb_oracle(plaintext):
    """
    Appends the unknown string, then encrypts in ECB mode using the random global key.

    Args:
        plaintext: Plaintext to encrypt as bytes.

    Returns:
        bytes: Resulting ciphertext.
    """
    appended_plaintext = plaintext + APPEND_BYTES
    appended_plaintext_padded = pkcs7_pad(appended_plaintext)
    ciphertext = AES_CIPHER.encrypt(appended_plaintext_padded)
    return ciphertext

# detect block size
# ciphertext is always integer multiple of block size
# the amount added to the next biggest ciphertext is block size
jump = 0
plaintext = b"A"
ciphertext = ecb_oracle(plaintext)
initial_ciphertext_length = len(ciphertext)
while jump == 0:
    plaintext += b"A"
    ciphertext = ecb_oracle(plaintext)
    ciphertext_length = len(ciphertext)
    jump = ciphertext_length - initial_ciphertext_length
block_size = jump

# detect ecb
# gurantees two identical blocks
plaintext = b"A" * (2*block_size)
ciphertext = ecb_oracle(plaintext)
if detect_ecb(ciphertext):
    # need to know how long the mystery text is
    # this will actually get mystery text plus padding
    # so it as an upper bound on the length
    target_length = len(ecb_oracle(b""))
    num_blocks = target_length // block_size
    curr_known = b""
    for block_num in range(num_blocks):
        curr_block = b""
        for i in range(block_size):
            short_plaintext = b"A" * (block_size - (i+1))
            chosen_plaintext = short_plaintext + curr_known + curr_block

            possibilities = {ecb_oracle(chosen_plaintext + bytes([b]))[block_num*block_size:(block_num+1)*block_size] 
                             : bytes([b]) for b in range(256)}
            
            correct_byte = possibilities.get(ecb_oracle(short_plaintext)[block_num*block_size:(block_num+1)*block_size])
            if correct_byte is None:
                # Reached the end
                break
            curr_block += correct_byte
        curr_known += curr_block

    print(curr_known.decode("ascii"))
else:
    print("Not ECB")
