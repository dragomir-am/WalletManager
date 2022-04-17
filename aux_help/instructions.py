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


# valid_entropy_bit_sizes = [128, 160, 192, 224, 256]
# TO DO HERE: CHANGE ENTROPY SIZE TO 256
entropy_bit_size = 128
# TO DO HERE: FIND BETTER RANDOM GENERATOR OR CREATE ONE
entropy_bytes = os.urandom(entropy_bit_size // 8)
print(entropy_bytes)
# b'Q\x83\xe1\xf4\xf1j\xac5\x16\x04<\x0bm`\xcf\x0c'

entropy_bits = bitarray()
entropy_bits.frombytes(entropy_bytes)
print(entropy_bits)

# bitarray('0101000110000011...01100111100001100')

# We’re expecting 12 mnemonic words in the end, so we’re going to
# want to chop up our data into 12 groups. 128 bits is not evenly divisible by 12, though. The BIP 39 formula
# accounts for this by adding a checksum to the end of the entropy. The size of the checksum is dependent on the size
# of the entropy. To find the checksum length, divide the entropy size (e.g. 128) by 32:

checksum_length = entropy_bit_size // 32
print(checksum_length)
# 4

# So, we know that the checksum will be four bits in length.
# Which four bits? The first four of the SHA-256 hash of the entropy:

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

# The first 4 bits in this case are 1110. This checksum gets appended to the end of the
# entropy_bits, bringing the total bits to 132 — a number evenly divisible into 12 groups of 11 bits.
print(len(entropy_bits))
# 128
entropy_bits.extend(checksum)
print(len(entropy_bits))
# 132

# 11 bits is the “magic number” chosen in the BIP 39 spec. Regardless of entropy size, the entropy + checksum needs
# to be evenly divided into groups of 11 bits. The following Python one-liner does just that:
grouped_bits = tuple(entropy_bits[i * 11: (i + 1) * 11] for i in range(len(entropy_bits) // 11))
print(grouped_bits)
# (bitarray('01010001100'), bitarray('00011111000'), ...)
print(len(grouped_bits))
# 12

# The next step is to convert each 11-bit group into integers. The bitarray package provides a convenient helper
# function, ba2int, for converting bit arrays to integers. The resulting integers should range from zero to 2047 (
# i.e., ba2int(bitarray(‘11111111111’)) == 2047).

indices = tuple(ba2int(ba) for ba in grouped_bits)
print(indices)
# (652, 248, 1001, 1814, 1366, 212, 704, 1084, 91, 856, 414, 206)

# For this example, we’ll assume the English word list is already loaded into memory.
# Simply swap out the English word at the corresponding index to reveal your mnemonic:

with open('english.txt', 'r') as f:
    english_word_list = [line.strip() for line in f]

mnemonic_words = tuple(english_word_list[i] for i in indices)
print(mnemonic_words)
# ('face', 'business', 'large', 'tissue', 'print', 'box', 'fix', 'maple', 'arena', 'help', 'critic', 'border')

# The 512-bit seed is produced by a Password-Based Key Derivation Function, and specifically, PBKDF2. The inputs to
# this function are the pseudorandom function (HMAC-SHA512), a password (our mnemonic sentence), a salt,
# and the number of iterations the hash function will run (2048). The only argument we haven’t covered yet is the
# salt. This is an opportunity to add an additional level of security to your wallets. To produce the salt,
# the string “mnemonic” is concatenated with an optional passphrase of your choosing. If you don’t supply one,
# the passphrase will default to an empty string.

passphrase = input("Your complex passphrase: ")
salt = "mnemonic" + passphrase

# That’s everything we need to derive the seed. In Python-land, hashlib’s pbkdf2_hmac function is the one we’re
# looking for. Note that the mnemonic sentence needs to be in string format, with the words separated by spaces.
# Then, both the mnemonic and the salt need to be converted to bytes

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

# The seed is returned as a set of 64 bytes (512 bits), but the hexadecimal format is how you would commonly see it
# represented. If you coded along at home, a quick way to check your work is to plug in the mnemonic sentence you
# generated into a hosted BIP 39 converter and see if the resulting seed matches yours. Want the code? Here’s that
# Jupyter notebook link again.

