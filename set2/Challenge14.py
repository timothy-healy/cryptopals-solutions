"""
Cryptopals Set 2, Challenge 14; Byte-at-a-time ECB decryption (Harder)

Take the oracle from challenge 12. Now, create a random number of random bytes,
and prepend this to every plaintext. Same goal, to decrypt the target bytes.
"""
from Crypto.Cipher import AES
import base64
import sys
import secrets
sys.path.append("..")
from utils import detect_block_size, detect_ecb, pkcs7_pad, gen_rand_key

RAND_KEY = gen_rand_key()
AES_CIPHER = AES.new(RAND_KEY, AES.MODE_ECB)
APPEND_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
APPEND_BYTES = base64.b64decode(APPEND_B64)
PREPEND_BYTES = secrets.token_bytes(secrets.randbelow(40))

def ecb_oracle(plaintext):
    """
    Prepends the random string, appends the unknown string,
    then encrypts in ECB mode using the random global key.

    Args:
        plaintext: Plaintext to encrypt as bytes.

    Returns:
        bytes: Resulting ciphertext.
    """
    appended_plaintext = PREPEND_BYTES + plaintext + APPEND_BYTES
    appended_plaintext_padded = pkcs7_pad(appended_plaintext)
    ciphertext = AES_CIPHER.encrypt(appended_plaintext_padded)
    return ciphertext


block_size = detect_block_size(ecb_oracle)
# detect length of random prepended string
# input bigger plaintexts until two identical blocks are detected
# as soon as 2 blocks are detected, prefix + plaintext blocks
plaintext = b"a" * 2 * block_size
detected = detect_ecb(ecb_oracle(plaintext))
counter = 0
while not detected[0] and counter < block_size:
    plaintext += b"a"
    counter += 1
    detected = detect_ecb(ecb_oracle(plaintext))

if counter == block_size and not detected[0]:
    # should find it within a block_size worth of iterations
    print("Not ECB")
    sys.exit()


success_length = len(plaintext)
first_block = detected[1][0]
second_block = detected[1][1]
assert first_block == second_block-1, f"Identical blocks not consecutive: {first_block} and {second_block}"
prefix_length = ((second_block+1)*block_size) - success_length

# now need to fill in the prefix so that it is length 0 mod 16
# then can proceed like challenge 12
NEUTRALIZE_PREFIX = b"a" * (block_size - (prefix_length % block_size))
assert (len(NEUTRALIZE_PREFIX) + prefix_length) % block_size == 0, "Prefix not neutralized"

# need to know how long the mystery text is
# this will actually get mystery text plus padding
# so it as an upper bound on the length
plaintext = NEUTRALIZE_PREFIX
initial_length = len(ecb_oracle(plaintext))
upper_bound = initial_length - prefix_length - len(plaintext)
num_blocks = upper_bound // block_size

# now find the actual length
jump = 0
while jump == 0:
    plaintext += b"a"
    ciphertext = ecb_oracle(plaintext)
    jump = len(ciphertext) - initial_length
actual_length = len(ciphertext) - len(plaintext) - block_size - prefix_length
assert actual_length <= upper_bound, f"Length or upper bound calculated incorrectly. Length: {actual_length}; Upper bound: {upper_bound}"
assert actual_length >= 0, f"Length calculated is negative: {actual_length}"
last_block_length = actual_length % block_size

curr_known = b""
for block_num in range(num_blocks):
    curr_block = b""
    for i in range(block_size):
        if block_num == num_blocks-1 and i == last_block_length:
            # done with actual data, now just at padding
            break
        short_plaintext = b"A" * (block_size - (i+1))
        chosen_plaintext = NEUTRALIZE_PREFIX + short_plaintext + curr_known + curr_block
        # just need to shift which blocks are looked at
        shift = (prefix_length + len(NEUTRALIZE_PREFIX)) // block_size
        
        possibilities = {ecb_oracle(chosen_plaintext + bytes([b]))[(block_num + shift)*block_size:(block_num + 1 + shift)*block_size] 
                            : bytes([b]) for b in range(256)}
        
        correct_byte = possibilities.get(ecb_oracle(NEUTRALIZE_PREFIX + short_plaintext)[(block_num + shift)*block_size:(block_num + 1 + shift)*block_size])
        # with the check at the top of the loop, should never venture into padding
        # so should always find a correct byte
        assert correct_byte is not None, f"No correct byte found in block {block_num} and i={i}"
        curr_block += correct_byte
    curr_known += curr_block

print(curr_known.decode("ascii"))
