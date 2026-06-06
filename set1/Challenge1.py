"""
Cryptopals Set 1, Challenge 1; Converting hex to base 64.
Hex to base64

The (hex) string
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
should convert to
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
in base64.
"""
import base64

def hex_to_base64(hex_string):
    bytes_string = bytes.fromhex(hex_string)
    b64_string = base64.b64encode(bytes_string)
    return b64_string


result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
print(result)
