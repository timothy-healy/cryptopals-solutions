"""
Cryptopals Set 1, Challenge 2; XOR operation

Write a function that XOR's two equal length byte strings.

Given test:
1c0111001f010100061a024b53535009181c
when XOR'd against
686974207468652062756c6c277320657965
should produce
746865206b696420646f6e277420706c6179
"""
from utils import xor_bytes

target = "746865206b696420646f6e277420706c6179"

bytes1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
bytes2 = bytes.fromhex("686974207468652062756c6c277320657965")
result = xor_bytes(bytes1, bytes2).hex()

print(result)
print(result==target)
