from wallet_constructor.cryptocurrencies import BitcoinMainnet, LitecoinMainnet, DogecoinMainnet, EthereumMainnet


class User:
    def __init__(self):
        self.email = ""
        self.password = ""
        self.otp = ""


class WalletDetails:
    def __init__(self):
        self.language = {
            0: "chinese_simplified",
            1: "chinese_traditional",
            2: "english",
            3: "french",
            4: "italian",
            5: "japanese",
            6: "korean",
            7: "spanish"
        }
        self.account = 0
        self.currency_class = {
            'Bitcoin': BitcoinMainnet,
            'Litecoin': LitecoinMainnet,
            'Dogecoin': DogecoinMainnet,
            'Ethereum': EthereumMainnet
        }
        self.change = {
            0: False,
            1: True
        }
        self.passphrase = ""
        self.account_limit_reached = False
        self.address_limit_reached = False
        self.mnemonic = ""
        self.wallet_generated = ""
        self.wallet_name = ""

        # self.accounts_number = str(db.get_number_of_accounts())
        # self.wallets_number = str(db.get_number_of_wallets())


class ExternalWallets:
    def __init__(self):
        self.currency = ""
        self.public_key = ""
        self.private_key = ""
