
from web3 import Web3, HTTPProvider

from blockchain.error_catch import InfuraErrorException


class Infura:
    """Abstraction over Infura node connection."""

    def __init__(self):
        # testnet url
        self.w3 = Web3(HTTPProvider("https://rinkeby.infura.io/v3/c8433d8086ef4c339da04ebd294c523a"))
        # TODO: load environment variables as API key
        pass

    def get_web3(self):
        if not self.w3.isConnected():
            raise InfuraErrorException()

        return self.w3

i = Infura()
address = '0x0708F87A089a91C65d48721Aa941084648562287'
a = i.w3.eth.get_balance(address)
print(a)
# import CryptGo
# import os
# print(Crypto.__file__);
# print (dir(Crypto));
# print(os.listdir(os.path.dirname(Crypto.__file__)))
