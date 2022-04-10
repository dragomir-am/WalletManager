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

