"""
Cryptopals Set 1, Challenge 5; Implement repeating-key XOR

Encrypt:
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

under repeating-key XOR using the key: ICE

Given expected result:
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
"""
import sys

sys.path.append("..")
from utils import repeating_key_xor

key = b"ICE"
plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
ciphertext = repeating_key_xor(plaintext, key).hex()
print(ciphertext)

expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
print(ciphertext == expected)
