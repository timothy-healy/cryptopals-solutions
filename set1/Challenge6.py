"""
Cryptopals Set 1, Challenge 6; Break repeating-key XOR

The given file in base64 has been encrypted with
repeating-key XOR. Decrypt it.
"""
import sys
import base64

sys.path.append("..")
from utils import xor_bytes, repeating_key_xor, break_single_xor

def hamming(bytes1, bytes2):
    """
    Calculates the hamming distance of two equal length byte strings.

    Args:
        bytes1: First byte string.
        bytes2: Second byte string, same length as first.

    Returns:
        int: The calculated hamming distance between the inputs.
    """
    distance = 0
    # 1 in XOR output means bits were different
    xor = xor_bytes(bytes1, bytes2)
    for b in xor:
        distance += bin(b).count("1")
    return distance

def transpose(input_bytes, size):
    """
    Transposes a string of bytes using the given size.

    Args:
        input_bytes: String of bytes to be transposed.
        size: Size of each transposed block.
    
    Returns:
        list: Each element is a transposed block of bytes.
    """
    return [input_bytes[i::size] for i in range(size)]

def score_keysize(ciphertext):
    """
    Scores each key length from 2-40 (inclusive) based on how likely it is the correct
    length of the repeating key for the cipher.

    Args:
        ciphertext: Ciphertext as bytes.

    Returns:
        list: Tuples of (normalized hamming distance, keysize), sorted ascending by distance.
    """
    # collect all hamming distances
    distances = []
    # trying suggested range of keysizes
    for keysize in range(2, 41):
        total = 0
        num_blocks = len(ciphertext)//keysize
        # getting hamming distance for all sequential pairs of blocks
        # rather than only the first few; then taking the average
        for i in range(num_blocks-1):
            bytes1 = ciphertext[i*keysize:(i+1)*keysize]
            bytes2 = ciphertext[(i+1)*keysize:(i+2)*keysize]
            # divide total distance by keysize to normalize
            total += hamming(bytes1, bytes2)/keysize
        average_distance = total/(num_blocks-1)
        distances.append((average_distance, keysize))

    distances.sort()
    return distances

def find_repeating_key(ciphertext, keysize):
    """
    Finds the key for a repeating key XOR cipher.

    Args:
        ciphertext: Ciphertext as bytes.
        keysize: Length of the repeating key.

    Returns:
        bytes: The repeating key for the cipher.
    """
    transposed_blocks = transpose(ciphertext, keysize)
    # each block is now a single character XOR problem
    key = bytes([break_single_xor(block)[1] for block in transposed_blocks])
    return key

def break_repeating_xor(ciphertext):
    """
    Breaks a repeating key XOR cipher.

    Args:
        ciphertext: Ciphertext as bytes.

    Returns:
        tuple:
            - bytes: Decrypted plaintext.
            - bytes: The repeating key for the cipher.
    """
    # find keysize -> find key -> decrypt
    distances = score_keysize(ciphertext)
    best_keysize = distances[0][1]
    key = find_repeating_key(ciphertext, best_keysize)
    plaintext = repeating_key_xor(ciphertext, key)
    return plaintext, key

### Tests ###
# Given test case
test1 = b"this is a test"
test2 = b"wokka wokka!!!"
# Hamming distance should be 37
assert hamming(test1, test2) == 37


### Attack ###
with open("Challenge6.txt", "r") as ciphertext_b64:
    ciphertext = base64.b64decode(ciphertext_b64.read())

plaintext, key = break_repeating_xor(ciphertext)
plaintext_str = plaintext.decode("ascii")

print(f"The key is: {key}")
print(f"The plaintext is:\n{plaintext_str}")
