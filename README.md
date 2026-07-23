# cryptopals-solutions
This repository is for documenting my progress through the [cryptopals challenges](https://www.cryptopals.com/),
a collection of exercises designed to demonstrate attacks on real-world crypto and
provide an avenue to learn about the underlying concepts.

Solutions are written in Python.
Any reusable function created in the course of a challenge is in utils.py

**Progress:** Currently through Set 2, Challenge 16

## Set 1: Basics
This set is on the basics, mainly covering XOR ciphers and introductory cryptanalysis.
- Implemented single-character XOR and repeating-key XOR
- Frequency analysis to break both of these ciphers
- Hamming distance-based keysize detection
- Introduction to AES and ECB detection

## Set 2: Block Crypto
This set is the first on block cipher cryptography, described as bread-and-butter crypto.
- Implemented AES in CBC mode
- Two levels of a byte-at-a-time attack on ECB mode
- ECB cut-and-paste
- CBC bitflipping attack
