from types import SimpleNamespace
from typing import Any, Optional

import inspect
import sys


class NestedNamespace(SimpleNamespace):
    def __init__(self, dictionary, **kwargs):
        super().__init__(**kwargs)
        for key, value in dictionary.items():
            if isinstance(value, dict):
                self.__setattr__(key, NestedNamespace(value))
            else:
                self.__setattr__(key, value)


class SegwitAddress(NestedNamespace):
    HRP: Optional[str] = None
    VERSION: int = 0x00


class CoinType(NestedNamespace):
    INDEX: int
    HARDENED: bool

    def __str__(self):
        return f"{self.INDEX}'" if self.HARDENED else f"{self.INDEX}"


class ExtendedKey(NestedNamespace):
    P2PKH: int
    P2SH: int

    P2WPKH: Optional[int] = None
    P2WPKH_IN_P2SH: Optional[int] = None

    P2WSH: Optional[int] = None
    P2WSH_IN_P2SH: Optional[int] = None


class ExtendedPrivateKey(ExtendedKey):
    pass


class ExtendedPublicKey(ExtendedKey):
    pass


class Cryptocurrency(NestedNamespace):
    NAME: str
    SYMBOL: str
    NETWORK: str
    SOURCE_CODE: Optional[str]
    COIN_TYPE: CoinType

    SCRIPT_ADDRESS: int
    PUBLIC_KEY_ADDRESS: int
    SEGWIT_ADDRESS: SegwitAddress

    EXTENDED_PRIVATE_KEY: ExtendedPrivateKey
    EXTENDED_PUBLIC_KEY: ExtendedPublicKey

    MESSAGE_PREFIX: Optional[str]
    DEFAULT_PATH: str
    WIF_SECRET_KEY: int


class BitcoinMainnet(Cryptocurrency):
    NAME = "Bitcoin"
    SYMBOL = "BTC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bitcoin/bitcoin"
    COIN_TYPE = CoinType({
        "INDEX": 0,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class LitecoinMainnet(Cryptocurrency):
    NAME = "Litecoin"
    SYMBOL = "LTC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/litecoin-project/litecoin"
    COIN_TYPE = CoinType({
        "INDEX": 2,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x32
    PUBLIC_KEY_ADDRESS = 0x30
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "ltc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Litecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class DogecoinMainnet(Cryptocurrency):
    NAME = "Dogecoin"
    SYMBOL = "DOGE"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/dogecoin/dogecoin"
    COIN_TYPE = CoinType({
        "INDEX": 3,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x16
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x02fac398,
        "P2SH": 0x02fac398,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x02facafd,
        "P2SH": 0x02facafd,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Dogecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xf1


class EthereumMainnet(Cryptocurrency):
    NAME = "Ethereum"
    SYMBOL = "ETH"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/ethereum/go-ethereum"
    COIN_TYPE = CoinType({
        "INDEX": 60,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


def get_cryptocurrency(symbol: str) -> Any:
    for _, cryptocurrency in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cryptocurrency):
            if issubclass(cryptocurrency, Cryptocurrency) and cryptocurrency != Cryptocurrency:
                if symbol == cryptocurrency.SYMBOL:
                    return cryptocurrency

    raise ValueError(f"Invalid Cryptocurrency '{symbol}' symbol.")
