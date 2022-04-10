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


def generate_mnemonic(language, secret):
    wordlist = language.join("txt.")

    entropy_bit_size = 256
    entropy_bytes = os.urandom(entropy_bit_size // 8)

    entropy_bits = bitarray()
    entropy_bits.frombytes(entropy_bytes)

    checksum_length = entropy_bit_size // 32

    hash_bytes = sha256(entropy_bytes).digest()

    hash_bits = bitarray()
    hash_bits.frombytes(hash_bytes)

    checksum = hash_bits[:checksum_length]

    entropy_bits.extend(checksum)

    grouped_bits = tuple(entropy_bits[i * 11: (i + 1) * 11] for i in range(len(entropy_bits) // 11))
    indices = tuple(ba2int(ba) for ba in grouped_bits)

    with open(wordlist, 'r') as f:
        english_word_list = [line.strip() for line in f]

        mnemonic_words = tuple(english_word_list[i] for i in indices)
        print(mnemonic_words)

    passphrase = secret

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

    return seed, salt, mnemonic_string, passphrase
