import hashlib
import hmac
import struct
import unicodedata
from binascii import (
    hexlify, unhexlify
)
from hashlib import sha256
from typing import (
    Optional, Any, Union
)
from typing import (
    Tuple
)

import base58
import ecdsa
import sha3
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import (
    int_to_string, string_to_int
)
from ecdsa.ellipticcurve import Point
from ecdsa.keys import (
    SigningKey, VerifyingKey
)
from libs.base58 import (
    check_encode, checksum_encode, check_decode, ensure_string
)
from libs.bech32 import (
    encode
)
from libs.ecc import S256Point, G
from mnemonic import Mnemonic

from wallet_constructor import exceptions
from wallet_constructor.cryptocurrencies import (
    Cryptocurrency, get_cryptocurrency
)
from wallet_constructor.derivations import (
    Derivation, BIP44Derivation
)

from wallet_constructor.utils import (
    get_bytes, is_entropy, is_mnemonic, get_entropy_strength, _unhexlify, is_root_xpublic_key,
    get_mnemonic_language, is_root_xprivate_key, get_mnemonic_strength, get_semantic
)

MIN_ENTROPY_LEN: int = 128
BIP32KEY_HARDEN: int = 0x80000000

CURVE_GEN: Any = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER: int = CURVE_GEN.order()
FIELD_ORDER: int = SECP256k1.curve.p()
INFINITY: Point = ecdsa.ellipticcurve.INFINITY


class HDWallet:

    def __init__(self, symbol: str = "ETH", cryptocurrency: Any = None,
                 semantic: Optional[str] = None, use_default_path: bool = False):
        self._cryptocurrency: Any = None
        if cryptocurrency:
            if not issubclass(cryptocurrency, Cryptocurrency):
                raise TypeError("Invalid Cryptocurrency type, the sub class must be Cryptocurrency instance.")
            self._cryptocurrency: Any = cryptocurrency
        else:
            self._cryptocurrency: Any = get_cryptocurrency(symbol=symbol)

        self._strength: Optional[int] = None
        self._entropy: Optional[str] = None
        self._mnemonic: Optional[str] = None
        self._language: Optional[str] = None
        self._passphrase: Optional[str] = None

        self._use_default_path: bool = use_default_path
        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self._i: Optional[bytes] = None
        self._path: str = "m"

        self._seed: Optional[bytes] = None
        self._private_key: Optional[bytes] = None
        self._key: Optional[SigningKey] = None
        self._verified_key: Optional[VerifyingKey] = None
        self._semantic: str = semantic
        self._from_class: bool = False
        self._path_class: str = "m"

        self._root_private_key: Optional[tuple] = None
        self._root_public_key: Optional[tuple] = None
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[str] = None
        self._chain_code: Optional[bytes] = None
        self._depth: int = 0
        self._index: int = 0

        self._root_depth: int = 0
        self._root_parent_fingerprint: bytes = b"\0\0\0\0"
        self._root_index: int = 0

    def from_entropy(self, entropy: str, language: str = "english", passphrase: str = None) -> "HDWallet":

        if not is_entropy(entropy=entropy):
            raise ValueError("Invalid entropy.")
        if language and language not in ["english", "french", "italian", "japanese",
                                         "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
            raise ValueError("Invalid language, choose only the following options 'english', 'french', 'italian', "
                             "'spanish', 'chinese_simplified', 'chinese_traditional', 'japanese' or 'korean' languages.")

        self._strength = get_entropy_strength(entropy=entropy)
        self._entropy, self._language = unhexlify(entropy), language
        self._passphrase = str(passphrase) if passphrase else str()
        mnemonic = Mnemonic(language=self._language).to_mnemonic(data=self._entropy)
        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_mnemonic(self, mnemonic: str, language: str = None, passphrase: str = None) -> "HDWallet":

        if not is_mnemonic(mnemonic=mnemonic, language=language):
            raise ValueError("Invalid mnemonic words.")

        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._strength = get_mnemonic_strength(mnemonic=self._mnemonic)
        self._language = language if language else get_mnemonic_language(mnemonic=self._mnemonic)
        self._entropy = Mnemonic(language=self._language).to_entropy(self._mnemonic)
        self._passphrase = str(passphrase) if passphrase else str()
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_seed(self, seed: str) -> "HDWallet":


        self._seed = unhexlify(seed)
        self._i = hmac.new(b"Bitcoin seed", get_bytes(seed), hashlib.sha512).digest()
        il, ir = self._i[:32], self._i[32:]
        self._root_private_key = (il, ir)
        parse_il = int.from_bytes(il, "big")
        if parse_il == 0 or parse_il >= SECP256k1.order:
            raise ValueError("Bad seed, resulting in invalid key!")

        self._private_key, self._chain_code = il, ir
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        self._public_key = self.compressed()
        if self._from_class:
            self.from_path(path=self._path_class)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self

    def from_xprivate_key(self, xprivate_key: str, strict: bool = False) -> "HDWallet":


        if not is_root_xprivate_key(xprivate_key=xprivate_key, symbol=self._cryptocurrency.SYMBOL):
            if strict:
                raise ValueError("Invalid root xprivate key.")

        _deserialize_xprivate_key = self._deserialize_xprivate_key(xprivate_key=xprivate_key)
        self._root_depth, self._root_parent_fingerprint, self._root_index = (
            int.from_bytes(_deserialize_xprivate_key[1], "big"),
            _deserialize_xprivate_key[2],
            struct.unpack(">L", _deserialize_xprivate_key[3])[0]
        )
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_deserialize_xprivate_key[1], "big"),
            _deserialize_xprivate_key[2],
            struct.unpack(">L", _deserialize_xprivate_key[3])[0]
        )
        self._i = _deserialize_xprivate_key[5] + _deserialize_xprivate_key[4]
        self._root_private_key = (_deserialize_xprivate_key[5], _deserialize_xprivate_key[4])
        self._private_key, self._chain_code = self._i[:32], self._i[32:]
        self._key = ecdsa.SigningKey.from_string(_deserialize_xprivate_key[5], curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        if self._from_class:
            self.from_path(path=self._path_class)
        self._public_key = self.compressed()
        self._semantic = get_semantic(
            _cryptocurrency=self._cryptocurrency,
            version=_deserialize_xprivate_key[0],
            key_type="private_key"
        )
        return self

    def from_xpublic_key(self, xpublic_key: str, strict: bool = False) -> "HDWallet":

        if not is_root_xpublic_key(xpublic_key=xpublic_key, symbol=self._cryptocurrency.SYMBOL):
            if strict:
                raise ValueError("Invalid root xpublic key.")

        _deserialize_xpublic_key = self._deserialize_xpublic_key(xpublic_key=xpublic_key)
        self._root_depth, self._root_parent_fingerprint, self._root_index = (
            int.from_bytes(_deserialize_xpublic_key[1], "big"),
            _deserialize_xpublic_key[2],
            struct.unpack(">L", _deserialize_xpublic_key[3])[0]
        )
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_deserialize_xpublic_key[1], "big"),
            _deserialize_xpublic_key[2],
            struct.unpack(">L", _deserialize_xpublic_key[3])[0]
        )
        self._chain_code = _deserialize_xpublic_key[4]
        self._verified_key = ecdsa.VerifyingKey.from_string(
            _deserialize_xpublic_key[5], curve=SECP256k1
        )
        self._root_public_key = (
            _deserialize_xpublic_key[5], _deserialize_xpublic_key[4]
        )
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        if self._from_class:
            self.from_path(path=str(self._path_class).replace("'", ""))
        self._public_key = self.compressed()
        self._semantic = get_semantic(
            _cryptocurrency=self._cryptocurrency,
            version=_deserialize_xpublic_key[0],
            key_type="public_key"
        )
        return self

    def from_wif(self, wif: str) -> "HDWallet":


        raw = check_decode(wif)[:-1]
        if not raw.startswith(_unhexlify(self._cryptocurrency.WIF_SECRET_KEY)):
            raise ValueError(f"Invalid {self.cryptocurrency()} wallet important format.")

        self._private_key = raw.split(_unhexlify(self._cryptocurrency.WIF_SECRET_KEY), 1).pop()
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_private_key(self, private_key: str) -> "HDWallet":


        self._private_key = unhexlify(private_key)
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_public_key(self, public_key: str) -> "HDWallet":

        self._verified_key = ecdsa.VerifyingKey.from_string(
            unhexlify(public_key), curve=SECP256k1
        )
        self._public_key = self.compressed()
        return self

    def from_path(self, path: Union[str, Derivation]) -> "HDWallet":


        if isinstance(path, Derivation):
            path = str(path)
        elif str(path)[0:2] != "m/":
            raise ValueError("Bad path, please insert like this type of path \"m/0'/0\"! ")

        for index in path.lstrip("m/").split("/"):
            if "'" in index:
                self._derive_key_by_index(int(index[:-1]) + BIP32KEY_HARDEN)
                self._path += str("/" + index)
            else:
                self._derive_key_by_index(int(index))
                self._path += str("/" + index)
        return self

    def from_index(self, index: int, hardened: bool = False) -> "HDWallet":

        if not isinstance(index, int):
            raise ValueError("Bad index, Please import only integer number!")

        if hardened:
            self._path += ("/%d'" % index)
            self._derive_key_by_index(index + BIP32KEY_HARDEN)
        else:
            self._path += ("/%d" % index)
            return self._derive_key_by_index(index)

    def _derive_key_by_index(self, index) -> Optional["HDWallet"]:

        if not self._root_private_key and not self._root_public_key:
            raise ValueError("You can't derive this master key.")

        i_str = struct.pack(">L", index)
        if index & BIP32KEY_HARDEN:
            if self._key is None:
                raise exceptions.DerivationError("Hardened derivation path is invalid for xpublic key.")
            data = b"\0" + self._key.to_string() + i_str
        else:
            data = unhexlify(self.public_key()) + i_str

        if not self._chain_code:
            raise ValueError("You can't drive xprivate_key and private_key.")

        i = hmac.new(self._chain_code, data, hashlib.sha512).digest()
        il, ir = i[:32], i[32:]

        il_int = string_to_int(il)
        if il_int > CURVE_ORDER:
            return None

        if self._key:
            pvt_int = string_to_int(self._key.to_string())
            k_int = (il_int + pvt_int) % CURVE_ORDER
            if k_int == 0:
                return None
            secret = (b"\0" * 32 + int_to_string(k_int))[-32:]

            self._private_key, self._chain_code, self._depth, self._index, self._parent_fingerprint = (
                secret, ir, (self._depth + 1), index, unhexlify(self.finger_print())
            )
            self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()
        else:
            key_point = S256Point.parse(unhexlify(self.public_key()))
            left_point = il_int * G
            total = key_point + left_point

            self._chain_code, self._depth, self._index, self._parent_fingerprint = (
                ir, (self._depth + 1), index, unhexlify(self.finger_print())
            )
            self._verified_key = ecdsa.VerifyingKey.from_string(
                total.sec(), curve=SECP256k1
            )
        return self

    @staticmethod
    def _deserialize_xprivate_key(xprivate_key: str, encoded: bool = True) -> tuple:
        decoded_xprivate_key = check_decode(xprivate_key) if encoded else xprivate_key
        if len(decoded_xprivate_key) != 78:  # 156
            raise ValueError("Invalid xprivate key.")
        return (
            decoded_xprivate_key[:4], decoded_xprivate_key[4:5],
            decoded_xprivate_key[5:9], decoded_xprivate_key[9:13],
            decoded_xprivate_key[13:45], decoded_xprivate_key[46:]
        )

    @staticmethod
    def _deserialize_xpublic_key(xpublic_key: str, encoded: bool = True) -> tuple:
        decoded_xpublic_key = check_decode(xpublic_key) if encoded else xpublic_key
        if len(decoded_xpublic_key) != 78:  # 156
            raise ValueError("Invalid xpublic key.")
        return (
            decoded_xpublic_key[:4], decoded_xpublic_key[4:5],
            decoded_xpublic_key[5:9], decoded_xpublic_key[9:13],
            decoded_xpublic_key[13:45], decoded_xpublic_key[45:]
        )

    @staticmethod
    def _serialize_xkeys(version: bytes, depth: bytes, parent_fingerprint: bytes, index: bytes,
                         chain_code: bytes, data: bytes, encoded: bool = True) -> Optional[str]:
        try:
            raw = (version + depth + parent_fingerprint + index + chain_code + data)
            return check_encode(raw) if encoded else raw.hex()
        except TypeError:
            return None

    def root_xprivate_key(self, encoded: bool = True) -> Optional[str]:


        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PRIVATE_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        if not self._i:
            return None
        secret_key, chain_code = self._i[:32], self._i[32:]
        depth = bytes(bytearray([self._root_depth]))
        parent_fingerprint = self._root_parent_fingerprint
        index = struct.pack(">L", self._root_index)
        data = b"\x00" + secret_key
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def root_xpublic_key(self, encoded: bool = True) -> Optional[str]:

        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PUBLIC_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        if self._root_public_key:
            data, chain_code = (
                self._root_public_key[0], self._root_public_key[1]
            )
        elif not self._i:
            return None
        else:
            secret_key, chain_code = self._i[:32], self._i[32:]
            data = unhexlify(self.public_key(private_key=secret_key.hex()))
        depth = bytes(bytearray([self._root_depth]))
        parent_fingerprint = self._root_parent_fingerprint
        index = struct.pack(">L", self._root_index)
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xprivate_key(self, encoded=True) -> Optional[str]:


        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PRIVATE_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        if self.private_key() is None:
            return None
        data = b"\x00" + unhexlify(self.private_key())
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xpublic_key(self, encoded: bool = True) -> Optional[str]:


        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PUBLIC_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        data = unhexlify(self.public_key())
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def clean_derivation(self) -> "HDWallet":


        if self._root_private_key:
            self._path, self._path_class, self._depth, self._parent_fingerprint, self._index = (
                "m", "m", 0, b"\0\0\0\0", 0
            )
            self._private_key, self._chain_code = self._root_private_key
            self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()
        elif self._root_public_key:
            self._path, self._path_class, self._depth, self._parent_fingerprint, self._index = (
                "m", "m", 0, b"\0\0\0\0", 0
            )
            self._chain_code = self._root_public_key[1]
            self._verified_key = ecdsa.VerifyingKey.from_string(
                self._root_public_key[0], curve=SECP256k1
            )
        return self

    def uncompressed(self, compressed: Optional[str] = None) -> str:


        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        public_key = unhexlify(compressed) if compressed else unhexlify(self.compressed())
        x = int.from_bytes(public_key[1:33], byteorder='big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != public_key[0] % 2:
            y = p - y
        y = y.to_bytes(32, byteorder='big')
        return (public_key[1:33] + y).hex()

    def compressed(self, uncompressed: Optional[str] = None) -> str:


        _verified_key = ecdsa.VerifyingKey.from_string(
            unhexlify(uncompressed), curve=SECP256k1
        ) if uncompressed else self._verified_key
        padx = (b"\0" * 32 + int_to_string(
            _verified_key.pubkey.point.x()))[-32:]
        if _verified_key.pubkey.point.y() & 1:
            ck = b"\3" + padx
        else:
            ck = b"\2" + padx
        return hexlify(ck).decode()

    def private_key(self) -> str:

        return hexlify(self._key.to_string()).decode() if self._key else None

    def public_key(self, compressed: bool = True, private_key: Optional[str] = None) -> str:


        if private_key:
            key = ecdsa.SigningKey.from_string(
                unhexlify(private_key), curve=SECP256k1)
            verified_key = key.get_verifying_key()
            padx = (b"\0" * 32 + int_to_string(
                verified_key.pubkey.point.x()))[-32:]
            if verified_key.pubkey.point.y() & 1:
                ck = b"\3" + padx
            else:
                ck = b"\2" + padx
            return hexlify(ck).decode() if compressed else self.uncompressed(compressed=hexlify(ck).decode())
        return self.compressed() if compressed else self.uncompressed()

    def strength(self) -> Optional[int]:

        return self._strength if self._strength else None

    def entropy(self) -> Optional[str]:

        return hexlify(self._entropy).decode() if self._entropy else None

    def mnemonic(self) -> Optional[str]:

        return unicodedata.normalize("NFKD", self._mnemonic) if self._mnemonic else None

    def passphrase(self) -> Optional[str]:

        return str(self._passphrase) if self._passphrase else None

    def language(self) -> Optional[str]:

        return str(self._language) if self._language else None

    def cryptocurrency(self) -> Optional[str]:

        return str(self._cryptocurrency.NAME)

    def symbol(self) -> Optional[str]:

        return str(self._cryptocurrency.SYMBOL)

    def semantic(self) -> Optional[str]:

        return self._semantic if self._semantic else None

    def network(self) -> Optional[str]:

        return str(self._cryptocurrency.NETWORK)

    def seed(self) -> Optional[str]:

        return hexlify(self._seed).decode() if self._seed else None

    def path(self) -> Optional[str]:

        return str(self._path) if not self._path == "m" else None

    def chain_code(self) -> Optional[str]:

        return hexlify(self._chain_code).decode() if self._chain_code else None

    def hash(self, private_key: str = None):

        return hashlib.new("ripemd160", sha256(unhexlify(self.public_key(
            private_key=private_key if private_key else self.private_key()
        ))).digest()).hexdigest()

    def finger_print(self) -> str:

        return self.hash(self.private_key())[:8]

    def p2pkh_address(self) -> str:

        if self._cryptocurrency.SYMBOL in ["ETH", "ETHTEST"]:
            keccak_256 = sha3.keccak_256()
            keccak_256.update(unhexlify(self.uncompressed()))
            address = keccak_256.hexdigest()[24:]
            return checksum_encode(address, crypto="eth")

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hashlib.new("ripemd160", sha256(compressed_public_key).digest()).digest()
        network_hash160_bytes = _unhexlify(self._cryptocurrency.PUBLIC_KEY_ADDRESS) + public_key_hash
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2sh_address(self) -> str:

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hashlib.new("ripemd160", sha256(compressed_public_key).digest()).hexdigest()
        public_key_hash_script = unhexlify("76a914" + public_key_hash + "88ac")
        script_hash = hashlib.new("ripemd160", sha256(public_key_hash_script).digest()).digest()
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2wpkh_address(self) -> Optional[str]:

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hashlib.new("ripemd160", sha256(compressed_public_key).digest()).digest()
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(encode(self._cryptocurrency.SEGWIT_ADDRESS.HRP, 0, public_key_hash))

    def p2wpkh_in_p2sh_address(self) -> Optional[str]:

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hashlib.new('ripemd160', sha256(compressed_public_key).digest()).hexdigest()
        script_hash = hashlib.new('ripemd160', sha256(unhexlify("0014" + public_key_hash)).digest()).digest()
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2wsh_address(self) -> Optional[str]:

        compressed_public_key = unhexlify("5121" + self.compressed() + "51ae")
        script_hash = sha256(compressed_public_key).digest()
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(encode(self._cryptocurrency.SEGWIT_ADDRESS.HRP, 0, script_hash))

    def p2wsh_in_p2sh_address(self) -> Optional[str]:

        compressed_public_key = unhexlify("5121" + self.compressed() + "51ae")
        script_hash = unhexlify("0020" + sha256(compressed_public_key).hexdigest())
        script_hash = hashlib.new('ripemd160', sha256(script_hash).digest()).digest()
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def wif(self) -> Optional[str]:

        return check_encode(
            _unhexlify(self._cryptocurrency.WIF_SECRET_KEY) + self._key.to_string() + b"\x01") if self._key else None

    def dumps(self) -> dict:

        return dict(
            cryptocurrency=self.cryptocurrency(),
            symbol=self.symbol(),
            network=self.network(),
            strength=self.strength(),
            entropy=self.entropy(),
            mnemonic=self.mnemonic(),
            language=self.language(),
            passphrase=self.passphrase(),
            seed=self.seed(),
            root_xprivate_key=self.root_xprivate_key(),
            root_xpublic_key=self.root_xpublic_key(),
            xprivate_key=self.xprivate_key(),
            xpublic_key=self.xpublic_key(),
            uncompressed=self.uncompressed(),
            compressed=self.compressed(),
            chain_code=self.chain_code(),
            private_key=self.private_key(),
            public_key=self.public_key(),
            wif=self.wif(),
            finger_print=self.finger_print(),
            semantic=self.semantic(),
            path=self.path(),
            hash=self.hash(),
            addresses=dict(
                p2pkh=self.p2pkh_address(),
                p2sh=self.p2sh_address(),
                p2wpkh=self.p2wpkh_address(),
                p2wpkh_in_p2sh=self.p2wpkh_in_p2sh_address(),
                p2wsh=self.p2wsh_address(),
                p2wsh_in_p2sh=self.p2wsh_in_p2sh_address()
            )
        )


class BIP44HDWallet(HDWallet):

    def __init__(self, symbol: str = "ETH", cryptocurrency: Any = None,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super(BIP44HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic="p2pkh"
        )

        self._from_class = True
        self._path_class = BIP44Derivation(
            cryptocurrency=self._cryptocurrency, account=account, change=change, address=address
        )

    def address(self) -> str:

        return self.p2pkh_address()
