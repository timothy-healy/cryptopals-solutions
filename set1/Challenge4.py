"""
Cryptopals Set 1, Challenge 4; Finding XOR-encrypted string

One of the 60-character strings in the given file
has been encrypted by single character XOR. Find it.
"""
from collections import namedtuple
from utils import single_xor, scorer

# use namedtuples for tracking best scores
BestResults = namedtuple("BestResults", ["line", "candidate", "score", "key"])
BestKey = namedtuple("BestKey", ["score", "key"])
with open("Challenge4.txt", "r") as candidates:
    best_for_all = BestResults(0, "", float("-inf"), 0) # track highest performing string

    for line, candidate in enumerate(candidates, 1):
        candidate = candidate.strip()
        best_for_candidate = BestKey(float("-inf"), 0) # tracks best score and corresponding key for a particular string

        # check all possible keys for each string in the file
        for key in range(256):
            decrypted = single_xor(bytes.fromhex(candidate), key)
            score = scorer(decrypted)

            if score > best_for_candidate.score:
                best_for_candidate = BestKey(score, key)

        if best_for_candidate.score > best_for_all.score:
            best_for_all = BestResults(line, candidate, best_for_candidate.score, best_for_candidate.key)
            
plaintext = single_xor(bytes.fromhex(best_for_all.candidate), best_for_all.key)

print(f"The encrypted string was on line {best_for_all.line}")
print(f"The key was {best_for_all.key}")
print(f"The score was {best_for_all.score}")
print(plaintext.decode())
