from typing import (
    Union, Tuple, Any, Optional
)

from wallet_constructor.cryptocurrencies import Cryptocurrency
from wallet_constructor.exceptions import (
    DerivationError
)

HARDENED: Tuple[str, str] = ("'", "")


class Derivation:
    """
    Hierarchical Deterministic Wallet Derivation's
    :param path: Derivation path.
    :type path: str
    :param semantic: Extended semantic, defaults to ``P2PKH``.
    :type semantic: str
    :returns: Derivation -- Derivation instance.
    """

    PATH: str = "\0\0\0\0"
    SEMANTIC: str = "p2pkh"

    def __str__(self) -> str:
        return self.PATH

    def __init__(self, path: Optional[str] = None, semantic: str = "p2pkh"):

        if path:
            if not isinstance(path, str):
                raise DerivationError("Bad derivation path, Please import only str type!")
            elif path[0:2] != "m/":
                raise DerivationError("Bad path, please insert like this str type of \"m/0'/0\" path!")

            self.PATH = "m"
            for index in path.lstrip("m/").split("/"):
                self.PATH += f"/{int(index[:-1])}'" if "'" in index else f"/{int(index)}"

        self.SEMANTIC = semantic

    @classmethod
    def from_path(cls, path: str) -> "Derivation":
        """
        Derivation from path.
        :param path: Derivation path.
        :type path: str, Derivation
        :returns: Derivation -- Derivation instance."""

        if not isinstance(path, str):
            raise DerivationError("Bad derivation path, Please import only str type!")
        if path[0:2] != "m/":
            raise DerivationError("Bad path, please insert like this str type of \"m/0'/0\" path!")

        new_path = "m"
        for index in path.lstrip("m/").split("/"):
            new_path += f"/{int(index[:-1])}'" if "'" in index else f"/{int(index)}"

        return Derivation(path=new_path)

    def from_index(self, index: int, hardened: bool = False) -> "Derivation":
        """
        Derivation from path.
        :param index: Derivation index.
        :type index: int
        :param hardened: Hardened address, default to ``False``.
        :type hardened: bool
        :returns: Derivation -- Derivation instance."""

        if not isinstance(index, int):
            raise DerivationError("Bad derivation index, Please import only int type!")

        if self.PATH == "\0\0\0\0":
            self.PATH = ""
        self.PATH += (
            (f"/{index}'" if hardened else f"/{index}")
            if self.PATH.startswith("m/") else
            (f"m/{index}'" if hardened else f"m/{index}")
        )
        return self

    def clean_derivation(self) -> "Derivation":
        """
        Clean derivation path or indexes.
        :returns: Derivation -- Derivation instance.
        """

        self.PATH = "\0\0\0\0"
        return self


class BIP32Derivation(Derivation):
    """
    Hierarchical Deterministic Wallet BIP32 Derivation
    :param cryptocurrency: Cryptocurrency instance, default to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param purpose: Purpose index, default to ``0``.
    :type purpose: int, tuple
    :param coin_type: Coin type, default to ``0``.
    :type coin_type: int, tuple
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple
    :returns: BIP32Derivation -- BIP32Derivation instance.
    """

    PURPOSE: Tuple[int, bool]
    COIN_TYPE: Tuple[int, bool]
    ACCOUNT: Tuple[int, bool]
    CHANGE: bool
    ADDRESS: Tuple[int, bool]

    def __str__(self):
        if self.PATH == "\0\0\0\0":
            return f"m/{self.PURPOSE[0]}{HARDENED[0] if self.PURPOSE[1] else HARDENED[1]}" \
                   f"/{self.COIN_TYPE[0]}{HARDENED[0] if self.COIN_TYPE[1] else HARDENED[1]}" \
                   f"/{self.ACCOUNT[0]}{HARDENED[0] if self.ACCOUNT[1] else HARDENED[1]}" \
                   f"/{1 if self.CHANGE else 0}" \
                   f"/{self.ADDRESS[0]}{HARDENED[0] if self.ADDRESS[1] else HARDENED[1]}"
        return self.PATH

    def __init__(self, cryptocurrency: Any = None,
                 purpose: Union[int, Tuple[int, bool]] = 0,
                 coin_type: Union[int, Tuple[int, bool]] = 0,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):

        super(BIP32Derivation, self).__init__()

        self.PURPOSE, self.COIN_TYPE, self.ACCOUNT, self.CHANGE, self.ADDRESS = (
            purpose if isinstance(purpose, tuple) else (purpose, True),
            (
                (cryptocurrency.COIN_TYPE.INDEX, cryptocurrency.COIN_TYPE.HARDENED)
                if cryptocurrency else
                (coin_type if isinstance(coin_type, tuple) else (coin_type, True))
            ),
            account if isinstance(account, tuple) else (account, True),
            change,
            address if isinstance(address, tuple) else (address, False)
        )

        self.SEMANTIC = "p2pkh"

    def from_purpose(self, purpose: int, hardened: bool = True) -> "BIP32Derivation":
        """
        Derivation from purpose index.
        :param purpose: Purpose index.
        :type purpose: int
        :param hardened: Hardened, default to ``True``.
        :type hardened: bool
        :returns: BIP32Derivation -- BIP32Derivation instance.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("When you are using custom path, you can't set purpose.")
        if type(self).__name__ != "BIP32Derivation":
            raise TypeError(
                f"You can't set purpose for {type(self).__name__}, it's only for BIP32Derivation class."
            )
        self.PURPOSE = (purpose, hardened)
        return self

    def from_coin_type(self, coin_type: int, hardened: bool = True) -> "BIP32Derivation":
        """
        Derivation from Coin Type index.
        :param coin_type: Coin type index.
        :type coin_type: int
        :param hardened: Hardened, default to ``True``.
        :type hardened: bool
        :returns: BIP32Derivation -- BIP32Derivation instance.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("When you are using custom path, you can't set coin type.")
        self.COIN_TYPE = (coin_type, hardened)
        return self

    def from_account(self, account: int, hardened: bool = True) -> "BIP32Derivation":
        """
        Derivation from Account index.
        :param account: Coin type index.
        :type account: int
        :param hardened: Hardened, default to ``True``.
        :type hardened: bool
        :returns: BIP32Derivation -- BIP32Derivation instance.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("When you are using custom path, you can't set account.")
        self.ACCOUNT = (account, hardened)
        return self

    def from_change(self, change: bool) -> "BIP32Derivation":
        """
        Derivation from external Change.
        :param change: External change.
        :type change: bool
        :returns: BIP32Derivation -- BIP32Derivation instance.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("When you are using custom path, you can't set change.")
        self.CHANGE = change
        return self

    def from_address(self, address: int, hardened: bool = False) -> "BIP32Derivation":
        """
        Derivation from Address index.
        :param address: Address index.
        :type address: int
        :param hardened: Hardened, default to ``True``.
        :type hardened: bool
        :returns: BIP32Derivation -- BIP32Derivation instance.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("When you are using custom path, you can't set address.")
        self.ADDRESS = (address, hardened)
        return self

    def clean_derivation(self) -> "BIP32Derivation":
        self.PURPOSE, self.COIN_TYPE, self.ACCOUNT, self.CHANGE, self.ADDRESS = (
            (0, True), (0, True), (0, True), False, (0, False)
        )
        self.PATH = "\0\0\0\0"
        return self

    def purpose(self) -> str:
        """
        Gey Purpose index.
        :returns: str -- Purpose index.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("You can't get purpose from custom path.")
        return f"{self.PURPOSE[0]}{HARDENED[0] if self.PURPOSE[1] else HARDENED[1]}"

    def coin_type(self) -> str:
        """
        Gey Coin Type index.
        :returns: str -- Coin Type index.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("You can't get coin type from custom path.")
        return f"{self.COIN_TYPE[0]}{HARDENED[0] if self.COIN_TYPE[1] else HARDENED[1]}"

    def account(self) -> str:
        """
        Gey Account index.
        :returns: str -- Account index.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("You can't get account from custom path.")
        return f"{self.ACCOUNT[0]}{HARDENED[0] if self.ACCOUNT[1] else HARDENED[1]}"

    def change(self, number: bool = False) -> Union[str, bool]:
        """
        Gey external Change.
        :param number: Return type, default to ``False``.
        :type number: bool
        :returns: str -- External change index.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("You can't get change from custom path.")
        return f"{1 if self.CHANGE else 0}" if number else self.CHANGE

    def address(self) -> str:
        """
        Gey Address index.
        :returns: str -- Address index.
        """

        if self.PATH and self.PATH != "\0\0\0\0":
            raise DerivationError("You can't get address from custom path.")
        return f"{self.ADDRESS[0]}{HARDENED[0] if self.ADDRESS[1] else HARDENED[1]}"


class BIP44Derivation(BIP32Derivation):
    """
    Hierarchical Deterministic Wallet BIP44 Derivation
    :param cryptocurrency: Cryptocurrency instance.
    :type cryptocurrency: Cryptocurrency
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple
    :returns: BIP44Derivation -- BIP44Derivation instance.
    """

    PURPOSE: int = 44

    def __init__(self, cryptocurrency: Any,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super().__init__(
            cryptocurrency=cryptocurrency,
            purpose=self.PURPOSE,
            coin_type=cryptocurrency.COIN_TYPE,
            account=account,
            change=change,
            address=address
        )

        self.SEMANTIC = "p2pkh"
