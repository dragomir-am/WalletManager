from mnemonic import Mnemonic
from binascii import hexlify, unhexlify
from random import choice
from typing import AnyStr, Optional

import string
import os
import inspect
import unicodedata
import binascii

from wallet_constructor import cryptocurrencies
from wallet_constructor.cryptocurrencies import (
    get_cryptocurrency, Cryptocurrency
)
from libs.base58 import check_decode

# Alphabet and digits.
letters = string.ascii_letters + string.digits


def _unhexlify(integer: int):
    try:
        return unhexlify("0%x" % integer)
    except binascii.Error:
        return unhexlify("%x" % integer)


def get_semantic(_cryptocurrency: Cryptocurrency, version: bytes, key_type: str) -> str:
    for name, cryptocurrency in inspect.getmembers(cryptocurrencies):
        if inspect.isclass(cryptocurrency):
            if issubclass(cryptocurrency, cryptocurrencies.Cryptocurrency) and cryptocurrency == _cryptocurrency:
                if key_type == "private_key":
                    for key, value in inspect.getmembers(cryptocurrency.EXTENDED_PRIVATE_KEY):
                        if value == int(version.hex(), 16):
                            return key.lower()
                elif key_type == "public_key":
                    for key, value in inspect.getmembers(cryptocurrency.EXTENDED_PUBLIC_KEY):
                        if value == int(version.hex(), 16):
                            return key.lower()


def get_bytes(string: AnyStr) -> bytes:
    if isinstance(string, bytes):
        byte = string
    elif isinstance(string, str):
        byte = bytes.fromhex(string)
    else:
        raise TypeError("Agreement must be either 'bytes' or 'string'!")
    return byte


def generate_passphrase(length: int = 32) -> str:
    return str().join(choice(letters) for _ in range(length))


def generate_entropy(strength: int = 128) -> str:
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "Strength should be one of the following "
            "[128, 160, 192, 224, 256], but it is not (%d)."
            % strength
        )
    return hexlify(os.urandom(strength // 8)).decode()


def generate_mnemonic(language: str = "english", strength: int = 128) -> str:
    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "Strength should be one of the following "
            "[128, 160, 192, 224, 256], but it is not (%d)."
            % strength
        )

    return Mnemonic(language=language).generate(strength=strength)


def is_entropy(entropy: str) -> bool:
    try:
        return len(unhexlify(entropy)) in [16, 20, 24, 28, 32]
    except:
        return False


def is_mnemonic(mnemonic: str, language: Optional[str] = None) -> bool:
    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")
    try:
        mnemonic = unicodedata.normalize("NFKD", mnemonic)
        if language is None:
            for _language in ["english", "french", "italian",
                              "chinese_simplified", "chinese_traditional", "japanese", "korean", "spanish"]:
                valid = False
                if Mnemonic(language=_language).check(mnemonic=mnemonic) is True:
                    valid = True
                    break
            return valid
        else:
            return Mnemonic(language=language).check(mnemonic=mnemonic)
    except:
        return False


def get_entropy_strength(entropy: str) -> int:
    if not is_entropy(entropy=entropy):
        raise ValueError("Invalid entropy hex string.")

    length = len(unhexlify(entropy))
    if length == 16:
        return 128
    elif length == 20:
        return 160
    elif length == 24:
        return 192
    elif length == 28:
        return 224
    elif length == 32:
        return 256


def get_mnemonic_strength(mnemonic: str, language: Optional[str] = None) -> int:
    if not is_mnemonic(mnemonic=mnemonic, language=language):
        raise ValueError("Invalid mnemonic words.")

    words = len(unicodedata.normalize("NFKD", mnemonic).split(" "))
    if words == 12:
        return 128
    elif words == 15:
        return 160
    elif words == 18:
        return 192
    elif words == 21:
        return 224
    elif words == 24:
        return 256


def get_mnemonic_language(mnemonic: str) -> str:
    if not is_mnemonic(mnemonic=mnemonic):
        raise ValueError("Invalid mnemonic words.")

    language = None
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    for _language in ["english", "french", "italian",
                      "chinese_simplified", "chinese_traditional", "japanese", "korean", "spanish"]:
        if Mnemonic(language=_language).check(mnemonic=mnemonic) is True:
            language = _language
            break
    return language


def entropy_to_mnemonic(entropy: str, language: str = "english") -> str:
    if not is_entropy(entropy=entropy):
        raise ValueError("Invalid entropy hex string.")

    if language and language not in ["english", "french", "italian", "japanese",
                                     "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
        raise ValueError("Invalid language, use only this options english, french, "
                         "italian, spanish, chinese_simplified, chinese_traditional, japanese or korean languages.")

    return Mnemonic(language=language).to_mnemonic(unhexlify(entropy))


def mnemonic_to_entropy(mnemonic: str, language: Optional[str] = None) -> str:
    if not is_mnemonic(mnemonic=mnemonic, language=language):
        raise ValueError("Invalid mnemonic words.")

    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    language = language if language else get_mnemonic_language(mnemonic=mnemonic)
    return Mnemonic(language=language).to_entropy(mnemonic).hex()


def is_root_xprivate_key(xprivate_key: str, symbol: str) -> bool:
    decoded_xprivate_key = check_decode(xprivate_key)
    if len(decoded_xprivate_key) != 78:  # 78, 156
        raise ValueError("Invalid xprivate key.")
    cryptocurrency = get_cryptocurrency(symbol=symbol)
    semantic = get_semantic(_cryptocurrency=cryptocurrency, version=decoded_xprivate_key[:4], key_type="private_key")
    version = cryptocurrency.EXTENDED_PRIVATE_KEY.__getattribute__(
        semantic.upper()
    )
    if version is None:
        raise NotImplementedError(semantic)
    raw = f"{_unhexlify(version).hex()}000000000000000000"
    return decoded_xprivate_key.hex().startswith(raw)


def is_root_xpublic_key(xpublic_key: str, symbol: str) -> bool:
    decoded_xpublic_key = check_decode(xpublic_key)
    if len(decoded_xpublic_key) != 78:  # 78, 156
        raise ValueError("Invalid xpublic key.")
    cryptocurrency = get_cryptocurrency(symbol=symbol)
    semantic = get_semantic(_cryptocurrency=cryptocurrency, version=decoded_xpublic_key[:4], key_type="public_key")
    version = cryptocurrency.EXTENDED_PUBLIC_KEY.__getattribute__(
        semantic.upper()
    )
    if version is None:
        raise NotImplementedError(semantic)
    raw = f"{_unhexlify(version).hex()}000000000000000000"
    return decoded_xpublic_key.hex().startswith(raw)
