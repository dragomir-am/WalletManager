# Ethereum 201: Mnemonics - BIP39

# The first thing we’ll need is that random number, also referred to as entropy. The BIP 39 spec states that this
# entropy can only come in a few sizes: multiples of 32 bits, between 128 and 256. The larger the entropy,
# the more mnemonic words generated, and the greater the security of your wallets. For simplicity’s sake,
# we’ll choose a 128-bit entropy, from which we can expect to derive 12 mnemonic words. For reference, each 32 bits
# beyond 128 adds three more mnemonic words to the sentence — the upper bounds being 24 words, using a 256-bit random
# number.
import hashlib
import os
from bitarray import bitarray
from bitarray.util import ba2int
from hashlib import sha256

option_menu = input("Option: ")

if option_menu != 'create':
    exit()


entropy_bit_size = 256
entropy_bytes = os.urandom(entropy_bit_size // 8)
print(entropy_bytes)

entropy_bits = bitarray()
entropy_bits.frombytes(entropy_bytes)
print(entropy_bits)

checksum_length = entropy_bit_size // 32
print(checksum_length)

hash_bytes = sha256(entropy_bytes).digest()
print(hash_bytes)
# b'\xef\x88\xad\x02\x16\x7f\xa6y\xde\xa6T...'
hash_bits = bitarray()
hash_bits.frombytes(hash_bytes)
print(hash_bits)
# bitarray('111011111000100010...')
checksum = hash_bits[:checksum_length]
print(checksum)
# bitarray('1110')

print(len(entropy_bits))
# 128
entropy_bits.extend(checksum)
print(len(entropy_bits))
# 132

grouped_bits = tuple(entropy_bits[i * 11: (i + 1) * 11] for i in range(len(entropy_bits) // 11))
print(grouped_bits)
# (bitarray('01010001100'), bitarray('00011111000'), ...)
print(len(grouped_bits))
# 12

indices = tuple(ba2int(ba) for ba in grouped_bits)
print(indices)
# (652, 248, 1001, 1814, 1366, 212, 704, 1084, 91, 856, 414, 206)

with open('english.txt', 'r') as f:
    english_word_list = [line.strip() for line in f]

    mnemonic_words = tuple(english_word_list[i] for i in indices)
    print(mnemonic_words)
    # ('face', 'business', 'large', 'tissue', 'print', 'box', 'fix', 'maple', 'arena', 'help', 'critic', 'border')

passphrase = input("Your complex passphrase: ")

salt = "mnemonic" + passphrase

mnemonic_string = ' '.join(mnemonic_words)
print(mnemonic_string)

# 'across abstract shine ... uphold already club'
seed = hashlib.pbkdf2_hmac(
    "sha512",
    mnemonic_string.encode("utf-8"),
    salt.encode("utf-8"),
    2048
)

print(seed)
# b'\xcd@\xd0}\xbc\x17\xd6H\x00\x1c\xdc...'
print(len(seed))
# 64
print(seed.hex())


# cd40d07dbc17d648001cdc84473be584...


def get_seed():
    return seed


def get_salt():
    return salt


def get_mnemonic():
    return mnemonic_string


def get_passphrase():
    return passphrase



