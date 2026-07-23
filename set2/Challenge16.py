"""
Cryptopals Set 2, Challenge 16; CBC bitflipping attacks.

Under a random key, write two functions: one doing CBC encryption and the other doing CBC decryption.
The encryption function should first prepend the string "comment1=cooking%20MCs;userdata=" and
append the string ";comment2=%20like%20a%20pound%20of%20bacon". Do not allow ';' or '=' to be encrypted.
The decryption function should also determine if ";admin=true" is present in the plaintext.
Modify the ciphertext to make it return True.
"""
import secrets
import sys
sys.path.append("..")
from utils import gen_rand_key, decrypt_cbc, encrypt_cbc

# unknown to attacker
KEY = gen_rand_key()
IV = secrets.token_bytes(16)

# assumed known to attacker
BLOCK_SIZE = 16
PREPEND_STR = "comment1=cooking%20MCs;userdata="
APPEND_STR = ";comment2=%20like%20a%20pound%20of%20bacon"

def flip_last_bit(b):
    """
    Flips the last bit of the given byte.

    Args:
        b: The byte to operate on, represented as int.

    Returns:
        bytes: The resulting byte.
    """
    return bytes([b ^ 1])

def cbc_encrypt_oracle(input_str):
    """
    Encrypts the input in CBC mode, after prepending and appending the respective strings.

    Args:
        input_str: The input to be encrypted, as a str.

    Returns:
        bytes: Encrypted ciphertext.
    """
    input_str = input_str.replace(';', "%3b").replace('=', "%3d")

    plaintext_str = PREPEND_STR + input_str + APPEND_STR
    plaintext = bytes(plaintext_str, "ascii")

    return encrypt_cbc(plaintext, KEY, IV)

def cbc_decrypt_oracle(ciphertext):
    """
    Decrypts the given ciphertext in CBC mode and searches for ";admin=true".

    Args:
        ciphertext: The ciphertext to decrypt, as bytes.

    Returns:
        bool: True if ";admin=true" is present, False otherwise.
    """
    plaintext = decrypt_cbc(ciphertext, KEY, IV)
    plaintext_str = bytes.decode(plaintext, "ascii", errors="replace")

    if ";admin=true" in plaintext_str:
        return True
    return False

### Tests ###
# make sure I can't put ;admin=true in input
ciphertext = cbc_encrypt_oracle(";admin=true")
assert not cbc_decrypt_oracle(ciphertext)
print("; and = successfully ignored")

### Attack ###
# flipping last bit of ; gets :
# flipping last bit of = gets <
attack_input = ":admin<true"
rel_index1 = attack_input.index(':')
rel_index2 = attack_input.index('<')

initial_ciphertext = cbc_encrypt_oracle(attack_input)
# allowed to know the prepended string length: exactly two blocks
# so need to flip bits in the second block for them to show up in the third block (my input)
block_num = len(PREPEND_STR) // BLOCK_SIZE - 1 # only works because of perfect alignment of prefix
abs_index1 = (block_num*BLOCK_SIZE)+rel_index1
abs_index2 = (block_num*BLOCK_SIZE)+rel_index2

attack_ciphertext = (initial_ciphertext[:abs_index1] + flip_last_bit(initial_ciphertext[abs_index1])
                     + initial_ciphertext[abs_index1+1:abs_index2] + flip_last_bit(initial_ciphertext[abs_index2])
                     + initial_ciphertext[abs_index2+1:])
assert cbc_decrypt_oracle(attack_ciphertext)
print("Attack successful. admin=true")
