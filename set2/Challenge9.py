"""
Cryptopals Set 2, Challenge 9; Implement PKCS#7 padding.

Pad any block to a specific length by appending the number of bytes of padding to the end of the block.
"""
import sys

sys.path.append("..")
from utils import pkcs7_pad

# given test
test = b"YELLOW SUBMARINE"
# should need 4
print("Given test to pad to 20:")
print(pkcs7_pad(test, 20))

# shorter test
print("\nShorter test:")
print(pkcs7_pad(b"MEOW"))

# test with block already the right size
# should add a full block of padding
print("\nAlready full block test:")
print(pkcs7_pad(test))
