"""
Cryptopals Set 3, Challenge 17; CBC padding oracle.

Generate a random AES key, and create a function that randomly chooses one of the given strings
and encrypts it, returning the ciphertext and IV. Create a second function that takes the ciphertext,
decrypts it, and validates the padding, returning true or false based on whether it is valid or not.
The decryption function has a side channel leak: returning whether or not the padding is valid.
Exploit this to decrypt the string.
"""
import base64
import random
import secrets
import sys
sys.path.append("..")
from utils import encrypt_cbc, decrypt_cbc, gen_rand_key, PKCS7PaddingError, validate_pkcs7

KEY = gen_rand_key()
RAND_STRINGS = ("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93")

def cbc_padding_oracle_encrypt():
    """
    Chooses random string and encrypts it in CBC mode with a random IV.

    Returns:
        tuple:
            - bytes: Ciphertext.
            - bytes: IV.
    """
    plaintext_b64 = random.choice(RAND_STRINGS)
    plaintext = base64.b64decode(plaintext_b64)
    iv = secrets.token_bytes(16)
    ciphertext = encrypt_cbc(plaintext, KEY, iv)
    return ciphertext, iv

def cbc_padding_oracle_decrypt(ciphertext, iv):
    """
    Decrypts the given ciphertext and validates padding.

    Args:
        ciphertext: The ciphertext to decrypt, as bytes.
        iv: The IV used on this ciphertext, as bytes.

    Returns:
        bool: True if PKCS#7 padding is valid, False otherwise.
    """
    plaintext = decrypt_cbc(ciphertext, KEY, iv, strip=False)
    try:
        validate_pkcs7(plaintext)
    except PKCS7PaddingError:
        return False
    else:
        return True

### Tests ###
ciphertext, iv = cbc_padding_oracle_encrypt()
assert cbc_padding_oracle_decrypt(ciphertext, iv)
print("Oracle works.")

### Attack ###
block_size = 16
num_blocks = len(ciphertext) // block_size
ciphertext_blocks = [ciphertext[block_size*block_num:block_size*(block_num+1)] for block_num in range(num_blocks)]
plaintext_blocks = []

for block_num, curr_block in enumerate(ciphertext_blocks):
    if block_num == 0:
        prev_block = iv
    else:
        prev_block = ciphertext_blocks[block_num-1]

    # keep track of captured bytes
    curr_aes_decrypted_block = [0] * block_size
    curr_plaintext_block = [0] * block_size
    for i in range(1, block_size+1):
        # for each byte position, change one byte at a time
        # on pervious block to force valid padding in current block
        tamper_prev = list(prev_block[:block_size-i]) + ([0]*i)
        for j in range(block_size-i+1, block_size):
            # need to fill in the bytes for the end of padding
            tamper_prev[j] = curr_aes_decrypted_block[j] ^ i
        for b in range(256):
            # try all possible byte values to check which generates valid padding
            if i == 1 and b == prev_block[block_size-i]:
                # avoid accidentally making valid padding by using original byte
                continue
            tamper_prev[block_size-i] = b
            if cbc_padding_oracle_decrypt(curr_block, bytes(tamper_prev)):
                break
        # XOR is its own inverse
        curr_aes_decrypted_block[block_size-i] = i ^ b
        curr_plaintext_block[block_size-i] = prev_block[block_size-i] ^ curr_aes_decrypted_block[block_size-i]

    plaintext_blocks.append(bytes(curr_plaintext_block))

plaintext = validate_pkcs7(b"".join(plaintext_blocks))
print(bytes.decode(plaintext, "ascii"))
