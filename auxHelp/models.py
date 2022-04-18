from wallet_constructor.cryptocurrencies import BitcoinMainnet, LitecoinMainnet, DogecoinMainnet, EthereumMainnet


class User:
    def __init__(self):
        self.email = ""
        self.password = ""
        self.otp = ""


class WalletModel:
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
        self.quantity = 0
        self.currency = {
           0: BitcoinMainnet,
           1: LitecoinMainnet,
           2: DogecoinMainnet,
           3: EthereumMainnet
        }
        self.change = {
           0: 0,
           1: 1
        }
        self.passphrase = ""

