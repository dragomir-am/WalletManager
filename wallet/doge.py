from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import DOGE as SYMBOL
from typing import Optional

import json


def generate_doge_wallet(language, passphrase):
    # Choose strength 128, 160, 192, 224 or 256
    STRENGTH: int = 256  # Default is 128
    # Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
    LANGUAGE: str = language  # Default is english
    # Generate new entropy hex string
    ENTROPY: str = generate_entropy(strength=STRENGTH)
    # Secret passphrase for mnemonic
    PASSPHRASE:str = passphrase # ""

    # Initialize Bitcoin mainnet HDWallet
    hdwallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
    # Get Bitcoin HDWallet from entropy
    hdwallet.from_entropy(
        entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    )

    # Derivation from path
    # hdwallet.from_path("m/44'/0'/0'/0/0")
    # Or derivation from index
    hdwallet.from_index(44, hardened=True)
    hdwallet.from_index(0, hardened=True)
    hdwallet.from_index(0, hardened=True)
    hdwallet.from_index(0)
    hdwallet.from_index(0)

    # Print all Bitcoin HDWallet information's
    print(json.dumps(hdwallet.dumps(), indent=4, ensure_ascii=False))
