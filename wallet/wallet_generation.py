from wallet_constructor.cryptocurrencies import EthereumMainnet
from wallet_constructor.derivations import BIP44Derivation
from wallet_constructor.hd import BIP44HDWallet
from wallet_constructor.utils import generate_mnemonic
from aux_help.db_actions import Wallet_db
from wallet_constructor import derivations

db = Wallet_db()


def generate_eth_wallet(language, passphrase, coin, count, email) -> object:
    # Generate mnemonic words
    MNEMONIC: str = generate_mnemonic(language=language, strength=256)
    # Secret passphrase/password for mnemonic
    PASSPHRASE: str = passphrase
    #
    COIN: classmethod = coin

    # Initialize BIP44HDWallet object
    bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=COIN)
    # Generate BIP44HDWallet from mnemonic
    bip44_hdwallet.from_mnemonic(
        mnemonic=MNEMONIC, language="english", passphrase=PASSPHRASE
    )
    # Prepare BIP44 derivation indexes/paths
    bip44_hdwallet.clean_derivation()

    # Create derivation table
    db.create_derivation_wallet(coin=bip44_hdwallet.symbol())

    # Get wallet fingerprint to server as reference for derivation table
    fingerprint = str(bip44_hdwallet.finger_print())

    # Loop and derive number of addresses requested from path
    for address_index in range(count):
        # Derivation from BIP44 derivation path
        bip44_derivation: BIP44Derivation = BIP44Derivation(
            cryptocurrency=COIN, account=0, change=False, address=address_index
        )
        # Derive BIP44HDWallet addresses
        bip44_hdwallet.from_path(path=bip44_derivation)
        # Insert wallet derivation details in db
        db.insert_wallet_derivation(str(bip44_hdwallet.symbol()), str(address_index), str(bip44_hdwallet.path()),
                                    str(bip44_hdwallet.address()), str(("0x" + bip44_hdwallet.private_key())),
                                    fingerprint)

        bip44_hdwallet.clean_derivation()

    # Store and format wallet details
    wallet_dict = bip44_hdwallet.dumps()
    wallet_dict['path'] = str(derivations.BIP44Derivation(cryptocurrency=COIN))
    wallet_dict['email'] = email
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

    # Create core wallet table and insert wallet details into db
    db.create_wallet_table(complete_wallet_keys_list)
    db.insert_wallet_core(complete_wallet_keys_list, complete_wallet_values_list)


generate_eth_wallet("english", "alex", EthereumMainnet, 2, "test@yahoo.com")
