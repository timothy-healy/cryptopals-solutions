"""
Cryptopals Set 2, Challenge 13; ECB cut and paste.

Write a k=v parsing routine and a function that encodes a user profile in that format,
given an email address. Do not allow encoding metacharacters (& and =).
Generate a random AES key. Encrypt the user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() and the ciphertexts themselves, make a role=admin profile.
"""
import random
from Crypto.Cipher import AES
import sys
sys.path.append("..")
from utils import pkcs7_pad, strip_pkcs7

# assuming attacker knows this value
UID = 10
KEY = bytes([random.randint(0, 255) for i in range(16)])
AES_CIPHER = AES.new(KEY, AES.MODE_ECB)



def parse(data):
    """
    Parses the given data into a dictionary.

    Args:
        data: Data to be parsed as String.

    Returns:
        dictionary: Parsed data.
    """
    parsed = {}
    data = data.split('&')

    for datum in data:
        datum = datum.split('=')
        parsed[datum[0]] = datum[1]
    
    return parsed


def profile_for(email):
    """
    Creates a user profile for the given email with uid and role.

    Args:
        email: User email as String.

    Returns:
        String: Created profile.
    """
    if '&' in email or '=' in email:
        return ""
    
    email_list = ["email", email]
    uid_list = ["uid", str(UID)]
    role_list = ["role", "user"]

    email_string = '='.join(email_list)
    uid_string = '='.join(uid_list)
    role_string = '='.join(role_list)

    profile_list = [email_string, uid_string, role_string]

    profile = '&'.join(profile_list)

    return profile

def encrypt(profile):
    """
    Encrypts the given profile using AES in ECB mode.

    Args:
        profile: Profile to encrypt as String.

    Returns:
        ciphertext: Encrypted profile as bytes.
    """
    plaintext = bytes(profile, "ascii")
    plaintext = pkcs7_pad(plaintext)
    ciphertext = AES_CIPHER.encrypt(plaintext)
    return ciphertext

def decrypt_parse(ciphertext):
    """
    Decrypts and parses the given ciphertext into a profile.

    Args:
        ciphertext: Ciphertext to decrypt.

    Returns:
        dictionary: Decrypted and parsed profile data.
    """
    plaintext = AES_CIPHER.decrypt(ciphertext)

    plaintext = strip_pkcs7(plaintext)

    profile = plaintext.decode("ascii")
    return parse(profile)


### Given Tests ###
print(parse("foo=bar&baz=qux&zap=zazzle"))
user_profile = profile_for("foo@bar.com")
# metacharacter rejection
print("Profile with metacharacters:")
print(profile_for("foo@bar.com&role=admin"))

### Round Trip Test ###
print("Encryption/decryption loop check:")
encrypted_profile = encrypt(user_profile)
print(encrypted_profile)
decrypted_profile = decrypt_parse(encrypted_profile)
print(decrypted_profile)


### Attack ###
# 13 character email makes role= end a block
email = "louie@woo.com"

# 15 characters plus 11 of padding for the word admin and fake padding to occupy a block
admin_email = "tencharacsadmin" + (chr(11) * 11)

regular_ciphertext = encrypt(profile_for(email)) 

admin_ciphertext = encrypt(profile_for(admin_email))

# need 2 blocks from regular and the second from admin
# for email=louie@woo.com&uid=10&role= plus admin and padding
created_ciphertext = regular_ciphertext[:32] + admin_ciphertext[16:32]
print(decrypt_parse(created_ciphertext))
