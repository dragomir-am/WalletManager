import binascii
import datetime
import hashlib
import hmac
import os.path
from hashlib import sha256
import base58
from bitarray import bitarray
from bitarray.util import ba2int
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key
from eth_utils import keccak

filename = '{:%Y_%m_%d_%H_%M_%S}'.format(datetime.datetime.now())

filepath = 'C:\\Users\\drago\\PycharmProjects\\WalletManager\\storage\\'

file_complete = os.path.join(filepath, filename + ".txt")

file = open(file_complete, "w")

print('Date now: %s' % datetime.datetime.now())

entropy_bit_size = 256
entropy_bytes = os.urandom(entropy_bit_size // 8)
print(entropy_bytes)
file.write("Entropy_bytes: " + str(entropy_bytes) + '\n')

entropy_bits = bitarray()
entropy_bits.frombytes(entropy_bytes)
print(entropy_bits)
file.write("Entropy_bits: " + str(entropy_bits) + '\n')

checksum_length = entropy_bit_size // 32
print(checksum_length)
file.write("checksum_length: " + str(checksum_length) + '\n')

hash_bytes = sha256(entropy_bytes).digest()
print(hash_bytes)
file.write("hash_bytes: " + str(hash_bytes) + '\n')

# b'\xef\x88\xad\x02\x16\x7f\xa6y\xde\xa6T...'
hash_bits = bitarray()
hash_bits.frombytes(hash_bytes)
print(hash_bits)
file.write("hash_bits: " + str(hash_bits) + '\n')
# bitarray('111011111000100010...')
checksum = hash_bits[:checksum_length]
print(checksum)
file.write("checksum: " + str(checksum) + '\n')
# bitarray('1110')

print(len(entropy_bits))
# 128
file.write("len(entropy_bits): " + str(len(entropy_bits)) + '\n')
entropy_bits.extend(checksum)
print(len(entropy_bits))
# 132
file.write("entropy_bits.extend(checksum): " + str(len(entropy_bits)) + '\n')

grouped_bits = tuple(entropy_bits[i * 11: (i + 1) * 11] for i in range(len(entropy_bits) // 11))
print(grouped_bits)
# (bitarray('01010001100'), bitarray('00011111000'), ...)
print(len(grouped_bits))
# 12
file.write("grouped_bits: " + str(grouped_bits) + str(len(grouped_bits)) + '\n')

indices = tuple(ba2int(ba) for ba in grouped_bits)
print(indices)
file.write("indices: " + str(indices) + '\n')
# (652, 248, 1001, 1814, 1366, 212, 704, 1084, 91, 856, 414, 206)

user_wordlist = input("Choose between: spanish, czech, english, french, italian, korean, "
                      "portuguese,chinese_traditional, chinese_simplified ")
wordlist_path = 'C:\\Users\\drago\\PycharmProjects\\WalletManager\\dictionaries\\'
wordlist_complete = os.path.join(wordlist_path, user_wordlist + ".txt")

with open(wordlist_complete, 'r') as f:
    word_list = [line.strip() for line in f]

    mnemonic_words = tuple(word_list[i] for i in indices)
    print(mnemonic_words)
    file.write("mnemonic_words: " + str(mnemonic_words) + '\n')
    # ('face', 'business', 'large', 'tissue', 'print', 'box', 'fix', 'maple', 'arena', 'help', 'critic', 'border')

passphrase = input("Pick a passphrase: ")

salt = "mnemonic" + passphrase

mnemonic_string = ' '.join(mnemonic_words)
print(mnemonic_string)
file.write("mnemonic_string: " + mnemonic_string + '\n')

# 'across abstract shine ... uphold already club'
seed = hashlib.pbkdf2_hmac(
    "sha512",
    mnemonic_string.encode("utf-8"),
    salt.encode("utf-8"),
    2048
)

print(seed)
# b'\xcd@\xd0}\xbc\x17\xd6H\x00\x1c\xdc...'
file.write("seed: " + str(seed) + '\n')
print(len(seed))
# 64
file.write("len(seed): " + str(len(seed)) + '\n')
print(seed.hex())
file.write("(seed.hex()): " + str(seed.hex()) + '\n')
# cd40d07dbc17d648001cdc84473be584...

# Derive the master private key and chain code

# the HMAC-SHA512 `key` and `data` must be bytes:


I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
L, R = I[:32], I[32:]

master_private_key = int.from_bytes(L, 'big')
master_chain_code = R

print(f'master private key (hex): {hex(master_private_key)}')
print(f'master chain code (bytes): {master_chain_code}')
file.write(str(f'master private key (hex): {hex(master_private_key)}') + '\n')
file.write(str(f'master chain code (bytes): {master_chain_code}') + '\n')
# Derive the root key (extended private key)

VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}

version_bytes = VERSION_BYTES['mainnet_private']
depth_byte = b'\x00'
parent_fingerprint = b'\x00' * 4
child_number_bytes = b'\x00' * 4
key_bytes = b'\x00' + L

all_parts = (
    version_bytes,  # 4 bytes
    depth_byte,  # 1 byte
    parent_fingerprint,  # 4 bytes
    child_number_bytes,  # 4 bytes
    master_chain_code,  # 32 bytes
    key_bytes,  # 33 bytes
)

all_bytes = b''.join(all_parts)
root_key = base58.b58encode_check(all_bytes).decode('utf8')
print(f'root key: {root_key}')
file.write(str(f'root key: {root_key}') + '\n')
# Elliptic curve utility functions

SECP256k1_GEN = SECP256k1.generator


def serialize_curve_point(p):
    x, y = p.x(), p.y()
    if y & 1:
        return b'\x03' + x.to_bytes(32, 'big')
    else:
        return b'\x02' + x.to_bytes(32, 'big')


def curve_point_from_int(k):
    return Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point


# Define a fingerprint function
# A fingerprint is four bytes - a link between child and parent keys.


def fingerprint_from_priv_key(k):
    k = curve_point_from_int(k)
    k_compressed = serialize_curve_point(k)
    identifier = hashlib.new(
        'ripemd160',
        hashlib.sha256(k_compressed).digest(),
    ).digest()
    return identifier[:4]


# Define the child key derivation function
SECP256k1_ORD = SECP256k1.order


def derive_ext_private_key(private_key, chain_code, child_number):
    if child_number >= 2 ** 31:
        # Generate a hardened key
        data = b'\x00' + private_key.to_bytes(32, 'big')
    else:
        # Generate a non-hardened key
        p = curve_point_from_int(private_key)
        data = serialize_curve_point(p)

    data += child_number.to_bytes(4, 'big')

    hmac_bytes = hmac.new(chain_code, data, hashlib.sha512).digest()
    L, R = hmac_bytes[:32], hmac_bytes[32:]

    L_as_int = int.from_bytes(L, 'big')
    child_private_key = (L_as_int + private_key) % SECP256k1_ORD
    child_chain_code = R

    return child_private_key, child_chain_code


# Run the child key derivation function once per path depth
# We're deriving keys for the account at the "default" path: m/44'/60'/0'/0/0.

# Break each depth into integers (m/44'/60'/0'/0/0)
#    e.g. (44, 60, 0, 0, 0)
# If hardened, add 2*31 to the number:
#    e.g. (2**31 + 44, 2**31 + 60, 2**31 + 0, 0, 0)

path_numbers = (2147483692, 2147483708, 2147483648, 0, 0)

depth = 0
parent_fingerprint = None
child_number = None
private_key = master_private_key
chain_code = master_chain_code

for i in path_numbers:
    depth += 1
    print(f"depth: {depth}")
    file.write(str(f"depth: {depth}") + '\n')
    child_number = i
    print(f"child_number: {child_number}")
    file.write(str(f"child_number: {child_number}") + '\n')
    parent_fingerprint = fingerprint_from_priv_key(private_key)
    print(f"parent_fingerprint: {parent_fingerprint}")
    file.write(str(f"parent_fingerprint: {parent_fingerprint}") + '\n')
    private_key, chain_code = derive_ext_private_key(private_key, chain_code, i)
    print(f"private_key: {private_key}")
    file.write(str(f"private_key: {private_key}") + '\n')
    print(f"chain_code: {chain_code}\n")
    file.write(str(f"chain_code: {chain_code}") + '\n')

# Derive the extended private key

version_bytes = VERSION_BYTES['mainnet_private']
depth_byte = depth.to_bytes(1, 'big')
child_number_bytes = child_number.to_bytes(4, 'big')
key_bytes = b'\x00' + private_key.to_bytes(32, 'big')

all_parts = (
    version_bytes,  # 4 bytes
    depth_byte,  # 1 byte
    parent_fingerprint,  # 4 bytes
    child_number_bytes,  # 4 bytes
    chain_code,  # 32 bytes
    key_bytes,  # 33 bytes
)
all_bytes = b''.join(all_parts)
extended_private_key = base58.b58encode_check(all_bytes).decode('utf8')
print(f'xprv: {extended_private_key}')
file.write(str(f'xprv: {extended_private_key}') + '\n')

# Display the private key

print(f'private key: {hex(private_key)}')
file.write(str(f'private key: {hex(private_key)}') + '\n')
# Derive the public key

# Derive the public key Point:
p = curve_point_from_int(private_key)
print(f'Point object: {p}\n')
file.write(str(f'Point object: {p}') + '\n')
# Serialize the Point, p
public_key_bytes = serialize_curve_point(p)

print(f'public key (hex): 0x{public_key_bytes.hex()}')
file.write(str(f'public key (hex): 0x{public_key_bytes.hex()}') + '\n')
# Derive the public address

# Hash the concatenated x and y public key point values:
digest = keccak(p.x().to_bytes(32, 'big') + p.y().to_bytes(32, 'big'))

# Take the last 20 bytes and add '0x' to the front:
address = '0x' + digest[-20:].hex()

print(f'address: {address}')
file.write(str(f'address: {address}') + '\n')

