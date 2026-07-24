"""
Functions used to solve cryptopals challenges, and reused in other challenges.
Functions used for only one challenge, remain local to that challenge file.
"""
from Crypto.Cipher import AES
from itertools import cycle
import secrets

# frequency of each letter plus the space character in standard English
FREQ_DICT = {
" ":0.13,
"e":0.124167,
"t":0.0969225,
"a":0.0820011,
"i":0.0768052,
"n":0.0764055,
"o":0.0714095,
"s":0.0706768,
"r":0.0668132,
"l":0.0448308,
"d":0.0363709,
"h":0.0350386,
"c":0.0344391,
"u":0.028777,
"m":0.0281775,
"f":0.0235145,
"p":0.0203171,
"y":0.0189182,
"g":0.0181188,
"w":0.0135225,
"v":0.0124567,
"b":0.0106581,
"k":0.00393019,
"x":0.00219824,
"j":0.0019984,
"q":0.0009325,
"z":0.000599
}

# same frequencies but with the byte values of characters 
FREQ_BYTES_DICT = {ord(k):v for k,v in FREQ_DICT.items()}

# Utilities

def xor_bytes(bytes1, bytes2):
    """
    XOR two equal length byte strings.
    Originally written for Set 1, Challenge 2.

    Args:
        bytes1: First byte string.
        bytes2: Second byte string, same length as the first.
    
    Returns:
        bytes: XOR of the inputs.
    """
    return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])


def pkcs7_pad(block, block_size=16):
    """
    Pads given input to the desired block size according to PKCS#7 padding scheme.
    Originally written for Set 2, Challenge 9.

    Args:
        block: The bytes to be padded.
        block_size: The size to pad the bytes to, defaults to 16.

    Returns:
        bytes: The original bytes padded to the correct size
    """
    length = len(block)
    missing = block_size - (length % block_size)
    pad = bytes([missing] * missing)

    return block + pad

def strip_pkcs7(block):
    """
    Strips padding of PKCS#7 padding scheme.
    Originally written for Set 2, Challenge 14; applied to preceding challenges.

    Args:
        block: The padded bytes to be stripped.

    Returns:
        bytes: The original bytes stripped of padding.
    """
    length = len(block)
    num_padding = block[-1]
    return block[:length-num_padding]

class PKCS7PaddingError(Exception):
    """Exception raised for invalid PKCS#7 padding."""
    pass

def validate_pkcs7(plaintext, block_size=16):
    """
    Validates PKCS#7 padding, and strips it, if valid.
    Originally written for Set 2, Challenge 15.

    Args:
        plaintext: Padded plaintext to validate, as bytes.
        block_size: The int block size the plaintext should be padded to, defaults to 16.

    Returns:
        bytes: The original plaintext with padding stripped.
    """
    if len(plaintext) % block_size != 0:
        raise PKCS7PaddingError("Invalid Padding")
    
    last_byte = plaintext[-1]
    if last_byte == 0:
        raise PKCS7PaddingError("Invalid Padding")
    
    if last_byte > block_size:
        raise PKCS7PaddingError("Invalid Padding")

    for i in range(1, last_byte):
        if plaintext[-1-i] != last_byte:
            raise PKCS7PaddingError("Invalid Padding")
        
    return strip_pkcs7(plaintext)

def gen_rand_key(length=16):
    """
    Generates a random key of the given length.
    Consolidated random key generation across multiple challenges.

    Args:
        length: Length of key to be generated as int.

    Returns:
        bytes: The generated key.
    """
    return secrets.token_bytes(length)

# Encryption/decryption

def single_xor(message, key):
    """
    XOR every byte in message against a single character key.
    Originally written for Set 1, Challenge 3.

    Args:
        message: Input bytes to be XORed.
        key: Single character key as int.
    
    Returns:
        bytes: Result of the XOR operation.
    """
    return bytes([b ^ key for b in message])

def repeating_key_xor(message, key):
    """
    XOR message against a repeating key.
    Originally written for Set 1, Challenge 5.

    Args:
        message: Input bytes to be XORed.
        key: Key as bytes.

    Returns:
        bytes: Result of repeating key XOR.
    """
    return bytes([bm ^ bk for bm, bk in zip(message, cycle(key))])

def encrypt_cbc(plaintext, key, iv, block_size=16):
    """
    Encrypts a given plaintext in CBC mode.
    Originally written for Set 2, Challenge 10.

    Args:
        plaintext: Plaintext as bytes.
        key: Key as bytes for the ECB encryption portion.
        iv: Initialization vector as bytes.
        block_size: Block size to use, defaults to 16.

    Returns:
        bytes: Encrypted ciphertext.
    """
    aes_ecb = AES.new(key, AES.MODE_ECB)
    # need to pad when encrypting
    padded_plaintext = pkcs7_pad(plaintext, block_size)
    num_blocks = len(padded_plaintext) // block_size

    ciphertext = b""
    for i in range(num_blocks):
        # for each block, XOR then ECB encrypt
        curr_plain_block = padded_plaintext[i*block_size:(i+1)*block_size]

        if i == 0:
            xord_plain = xor_bytes(curr_plain_block, iv)
        else:
            prev_cipher_block = ciphertext[(i-1)*block_size:i*block_size]
            xord_plain = xor_bytes(curr_plain_block, prev_cipher_block)
        curr_cipher_block = aes_ecb.encrypt(xord_plain)
        ciphertext += curr_cipher_block
    
    return ciphertext

def decrypt_cbc(ciphertext, key, iv, block_size=16, strip=True):
    """
    Decrypts a given ciphertext in CBC mode.
    Originally written for Set 2, Challenge 10.

    Args:
        ciphertext: Ciphertext as bytes.
        key: Key as bytes for the ECB decryption portion.
        iv: Initialization vector as bytes.
        block_size: Block size to use, defaults to 16.
        strip: Bool to strip padding from plaintext, defaults to True.

    Returns:
        bytes: Decrypted plaintext.
    """
    aes_ecb = AES.new(key, AES.MODE_ECB)
    # ciphertext already padded
    num_blocks = len(ciphertext) // block_size

    plaintext = b""
    for i in range(num_blocks):
        # for each block, ECB decrypt, then XOR
        curr_block = ciphertext[i*block_size:(i+1)*block_size]
        aes_decrypted = aes_ecb.decrypt(curr_block)
        if i == 0:
            plaintext_block = xor_bytes(aes_decrypted, iv)
            plaintext += plaintext_block
        
        else:
            prev_block = ciphertext[(i-1)*block_size:i*block_size]
            plaintext_block = xor_bytes(aes_decrypted, prev_block)
            plaintext += plaintext_block

    if strip:
        return strip_pkcs7(plaintext)
    return plaintext

# Analysis/scoring tools

def scorer(plaintext):
    """
    Scores plaintext based on how much it resembles the English language.
    Originally written for Set 1, Challenge 3.

    Args:
        plaintext: Plaintext to be evaluated as bytes.
    
    Returns:
        float: The calculated score of the input.
    """
    score = 0
    for b in plaintext:
        # penalizing non-ASCII values
        if b > 127:
            score-=0.05
        # penalizing nonprintable ASCII values
        elif b < 32:
            score-=0.05
        else:
            b = b | 0x20 # normalizing to lowercase
            score+=FREQ_BYTES_DICT.get(b, 0)
        
    return score

# Breaking

def break_single_xor(ciphertext):
    """
    Breaks a single-character XOR cipher.
    Originally written for Set 1, Challenge 3.

    Args:
        ciphertext: Ciphertext as bytes.

    Returns:
        tuple:
            - bytes: Decrypted plaintext.
            - int: The key used to break the cipher.
    """
    best_score = float("-inf")
    best_key = 0
    # try every possible key and score each one
    for key in range(256):
        attempt = single_xor(ciphertext, key)
        score = scorer(attempt)
        if score > best_score:
            best_score = score
            best_key = key

    plaintext = single_xor(ciphertext, best_key)
    return plaintext, best_key

# Detection

def detect_block_size(oracle):
    """
    Detects the block size being used by the given oracle function.
    Originally written for Set 2, Challenge 12.

    Args:
        oracle: The oracle function to detect.

    Return:
        int: The block size being used.
    """
    # ciphertext is always integer multiple of block size
    # the amount added to the next biggest ciphertext is block size
    jump = 0
    plaintext = b"A"
    ciphertext = oracle(plaintext)
    initial_ciphertext_length = len(ciphertext)
    while jump == 0:
        plaintext += b"A"
        ciphertext = oracle(plaintext)
        ciphertext_length = len(ciphertext)
        jump = ciphertext_length - initial_ciphertext_length
    return jump

def detect_ecb(candidate, block_size=16):
    """
    Detects if a string of bytes was encrypted with AES in ECB mode
    by looking for repeated blocks.
    Originally written for Set 1, Challenge 8.

    Args:
        candidate: Possible ciphertext as bytes.
        block_size: Block size to use, defaults to 16.

    Returns:
        tuple:
            - bool: True if ECB detected, False otherwise.
            - tuple:
                - int: Block number of the first block.
                - int: Block number of the identical block.
    """
    candidate_length = len(candidate)
    num_blocks = candidate_length // block_size
    for i in range(num_blocks):
        block = candidate[i*block_size:(i+1)*block_size]
        # compare to all succeeding blocks
        for j in range(i+1, num_blocks):
            block_comparison = candidate[j*block_size:(j+1)*block_size]
            if block == block_comparison:
                # only care about finding one identical pair in the candidate, not all of them
                return True, (i, j)
    return False, (0,0)
