"""
Cryptopals Set 3, Challenge 18; Implement CTR, the stream cipher mode.

CTR mode adapts the AES block cipher into a stream cipher. Instead of directly encrypting
the plaintext, CTR mode AES encrypts a counter against the key. The resulting keystream is XORed with
the plaintext stream. Because of this, decrypting and encrypting are the same operation.

The given string "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
should decrypt to "something approximating English", per the Cryptopals challenge prompt.
"""
import base64
from Crypto.Cipher import AES
import sys
sys.path.append("..")
from utils import xor_bytes

def ctr_mode(stream, key, nonce_int=0, format=(64, "little", 64, "little")):
    """
    Encrypt/decrypt the given stream in CTR mode.

    Args:
        stream: The stream to encrypt, as bytes.
        key: Key, as bytes.
        nonce_int: The nonce to use, as an int. Defaults to 0.
        format: tuple:
                        - int: Bit length for nonce, defaults to 64.
                        - str: Denotes little or big endian for nonce, defaults to little.
                        - int: Bit length for counter, defaults to 64.
                        - str: Denotes little or big endian for counter, defaults to little.
    
    Returns:
        bytes: The resulting output.
    """
    if format[0] % 8 != 0 or format[2] % 8 != 0:
        raise ValueError("nonce and counter must have valid bit-length")
    if format[0] + format[2] != 128:
        raise ValueError("nonce and counter bytes must sum to 16")
    aes = AES.new(key, AES.MODE_ECB)
    output = b""

    if len(stream) % 16 == 0:
        num_blocks = len(stream) // 16
    else:
        num_blocks = len(stream) // 16 + 1

    nonce = int.to_bytes(nonce_int, length=format[0]//8, byteorder=format[1])
    for block_num in range(num_blocks):
        counter_stream = nonce + int.to_bytes(block_num, length=format[2]//8, byteorder=format[3])
        keystream = aes.encrypt(counter_stream)
        if block_num == num_blocks-1 and len(stream)%16 != 0:
            length = len(stream[block_num*16:])
            output +=  xor_bytes(keystream[:length], stream[block_num*16:])
        else:
            output += xor_bytes(keystream, stream[block_num*16:(block_num+1)*16])
    return output


### Given Test ###
test_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
test = base64.b64decode(test_b64)

print(ctr_mode(test, b"YELLOW SUBMARINE"))

### Other Tests ###
# Test 1; short
plaintext = b"MEOW"
ciphertext = ctr_mode(plaintext, b"YELLOW SUBMARINE", nonce_int=4)
decrypted = ctr_mode(ciphertext, b"YELLOW SUBMARINE", nonce_int=4)
assert plaintext == decrypted
print("MEOW successful")

# Test 2; exactly 16 bytes
plaintext = b"YELLOW SUBMARINE"
ciphertext = ctr_mode(plaintext, b"YELLOW SUBMARINE", nonce_int=35)
decrypted = ctr_mode(ciphertext, b"YELLOW SUBMARINE", nonce_int=35)
assert plaintext == decrypted
print("YELLOW SUBMARINE successful")

# Test 3; over 256 blocks
plaintext = b"\x00" * 260 * 16
ciphertext = ctr_mode(plaintext, b"YELLOW SUBMARINE", nonce_int=5)
decrypted = ctr_mode(ciphertext, b"YELLOW SUBMARINE", nonce_int=5)
assert plaintext == decrypted
print("Long test successful")

# Test 4; invalid format
try:
    ctr_mode(b"test", b"YELLOW SUBMARINE", format=(62, "little", 66, "little"))
except ValueError:
    print("Invalid format correctly rejected")
else:
    print("Did not reject 62 and 66 for being invalid bit lengths.")

# Test 5; other invalid format
try:
    ctr_mode(b"test", b"YELLOW SUBMARINE", format=(32, "little", 32, "little"))
except ValueError:
    print("Invalid format correctly rejected")
else:
    print("Did not reject 32 and 32 for not being 16 bytes total.")

# Test 6; nonstandard format
plaintext = b"MEOW"
ciphertext = ctr_mode(plaintext, b"YELLOW SUBMARINE", nonce_int=5, format=(32, "little", 96, "little"))
decrypted = ctr_mode(ciphertext, b"YELLOW SUBMARINE", nonce_int=5, format=(32, "little", 96, "little"))
assert plaintext == decrypted
print("Nonstandard format successful")
