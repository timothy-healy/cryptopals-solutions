"""
Cryptopals Set 2, Challenge 15; PKCS#7 padding validation.

Write a function that takes plaintext and determines if it has
valid PKCS#7 padding, stripping the padding if valid.
"""
import sys
sys.path.append("..")
from utils import strip_pkcs7, PKCS7PaddingError, validate_pkcs7

### Given Tests ###
## Correct Test ##
correct_test = b"ICE ICE BABY\x04\x04\x04\x04"
target = b"ICE ICE BABY"
try:
    stripped = validate_pkcs7(correct_test)
except PKCS7PaddingError as e:
    print(e)
else:
    assert stripped == target, "Stripped incorrectly"
    print(stripped)

## Incorrect Test 1 ##
incorrect_test1 = b"ICE ICE BABY\x05\x05\x05\x05"
try:
    stripped = validate_pkcs7(incorrect_test1)
except PKCS7PaddingError as e:
    print(e)
else:
    print(stripped)

## Incorrect Test 2 ##
incorrect_test2 = b"ICE ICE BABY\x01\x02\x03\x04"
try:
    stripped = validate_pkcs7(incorrect_test2)
except PKCS7PaddingError as e:
    print(e)
else:
    print(stripped)

### Other Edge Cases ###
## Edge 1 ##
edge1 = b"ICE ICE BABY\x00"
try:
    stripped = validate_pkcs7(edge1)
except PKCS7PaddingError as e:
    print(e)
else:
    print(stripped)

## Edge 2 ##
edge2 = b"ICE ICE BABY\xff"
try:
    stripped = validate_pkcs7(edge2)
except PKCS7PaddingError as e:
    print(e)
else:
    print(stripped)
