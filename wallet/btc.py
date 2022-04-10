import json
import os

import sqlitebiter
from hdwallet import HDWallet
from hdwallet.symbols import BTC as SYMBOL
from hdwallet.utils import generate_entropy
from utils.db_actions import Wallet_db
import sqlite3

db_actions = Wallet_db()


def generate_btc_wallet(language, passphrase):
    # Choose strength 128, 160, 192, 224 or 256
    STRENGTH: int = 256  # Default is 128
    # Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
    LANGUAGE: str = language  # Default is english
    # Generate new entropy hex string
    ENTROPY: str = generate_entropy(strength=STRENGTH)
    # Secret passphrase for mnemonic
    PASSPHRASE: str = passphrase  # ""

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

    # Get wallet nested dictionary
    wallet_dict = hdwallet.dumps()

    # Save dictionary of addresses first
    dict_addresses = wallet_dict['addresses']

    # Get list of dictionary addresses keys and values
    dict_addresses_list = list(dict_addresses.keys())
    dict_addresses_values = list(dict_addresses.values())

    # Remove dictionary of addresses from wallet dictionary
    del wallet_dict['addresses']

    # Get list of keys from wallet dictionary and list of values
    wallet_dict_list = list(wallet_dict.keys())
    wallet_values_list = list(wallet_dict.values())

    # Join wallet list of value and keys with addresses list of values and keys
    complete_wallet_keys_list = wallet_dict_list + dict_addresses_list
    complete_wallet_values_list = wallet_values_list + dict_addresses_values

    # Create wallet table in database
    db_actions.create_wallet_table(complete_wallet_keys_list)
    # Add wallet details in database
    db_actions.insert_btc_wallet(complete_wallet_keys_list, complete_wallet_values_list)


generate_btc_wallet("english", "password")
