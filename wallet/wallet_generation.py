from auxHelp.models import WalletDetails
from wallet_constructor.cryptocurrencies import EthereumMainnet
from wallet_constructor.derivations import BIP44Derivation
from wallet_constructor.hd import BIP44HDWallet
from wallet_constructor.utils import generate_mnemonic
from auxHelp.db_actions import Actions
from wallet_constructor import derivations

db = Actions()
w = WalletDetails()


def derive_from_wallet(wallet, count, change, account, class_coin):
    bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=class_coin)

    # bip44_hdwallet.clean_derivation()

    bip44_hdwallet.from_mnemonic(wallet['mnemonic'], wallet['language'], wallet['passphrase'])

    # Create derivation table
    db.create_derivation_wallet()

    # Get wallet fingerprint to server as reference for derivation table
    fingerprint = str(bip44_hdwallet.finger_print())

    # Loop and derive number of addresses requested from path
    for address_index in range(count):
        # Derivation from BIP44 derivation path
        bip44_derivation: BIP44Derivation = BIP44Derivation(
            cryptocurrency=class_coin, account=account, change=change, address=address_index
        )
        # Derive BIP44HDWallet addresses
        bip44_hdwallet.from_path(path=bip44_derivation)
        # Insert wallet derivation details in db
        if address_index == 0:
            fix_path = str(bip44_hdwallet.path())
            unique = db.check_derivation_address(fix_path)
            if unique is False:
                w.address_found = True
                return
            else:
                db.insert_wallet_derivation(str(bip44_hdwallet.symbol()), str(address_index), ("m/" + fix_path[17:]),
                                            str(bip44_hdwallet.address()), str(("0x" + bip44_hdwallet.private_key())),
                                            str(bip44_derivation.change(change)), str(bip44_derivation.account()),
                                            fingerprint)

        elif db.check_derivation_address(str(bip44_hdwallet.path())) is True:
            db.insert_wallet_derivation(str(bip44_hdwallet.symbol()), str(address_index), str(bip44_hdwallet.path()),
                                        str(bip44_hdwallet.address()), str(("0x" + bip44_hdwallet.private_key())),
                                        str(bip44_derivation.change(change)), str(bip44_derivation.account()),
                                        fingerprint)

        bip44_hdwallet.clean_derivation()


def generate_wallet(language, passphrase, coin, account, email) -> object:
    # Generate mnemonic words
    MNEMONIC: str = generate_mnemonic(language=language, strength=256)
    # Secret passphrase/password for mnemonic
    PASSPHRASE: str = passphrase
    # Language option for mnemonic generation
    LANGUAGE: str = language
    #
    COIN: classmethod = coin

    # Initialize BIP44HDWallet object
    bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=COIN)
    # Generate BIP44HDWallet from mnemonic
    bip44_hdwallet.from_mnemonic(
        mnemonic=MNEMONIC, language=LANGUAGE, passphrase=PASSPHRASE
    )

    # Store and format wallet details
    wallet_dict = bip44_hdwallet.dumps()
    wallet_dict['path'] = str(derivations.BIP44Derivation(cryptocurrency=COIN))
    wallet_dict['email'] = email
    wallet_dict['account'] = account
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


# generate_wallet("english", "alex", EthereumMainnet, 0, "test@yahoo.com")

wwallet = db.get_wallet_core("b3e12435")
# print(wallet)
derive_from_wallet(wwallet, 5, True, 5, EthereumMainnet)
print(w.address_found)