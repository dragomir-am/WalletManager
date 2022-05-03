from web3 import Web3, HTTPProvider
from requests import get
from datetime import datetime
from blockchain.error_catch import InfuraErrorException

API_KEY = "TBYEBSHDFE4A6T6ESZ99XE533GZ6UNGYZJ"
BASE_URL = "https://api.etherscan.io/api"
ETHER_VALUE = 10 ** 18


class Infura:
    """Abstraction over Infura node connection."""

    def __init__(self):
        # testnet url
        self.w3 = Web3(HTTPProvider("https://rinkeby.infura.io/v3/c8433d8086ef4c339da04ebd294c523a"))

        pass

    def get_web3(self):
        if not self.w3.isConnected():
            raise InfuraErrorException()

        return self.w3

# Whale Balance
# i = Infura()
# address = '0x0708F87A089a91C65d48721Aa941084648562287'
# a = i.w3.eth.get_balance(address)
# print(a)


def make_api_url(module, action, address, **kwargs):
    url = BASE_URL + f"?module={module}&action={action}&address={address}&apikey={API_KEY}"

    for key, value in kwargs.items():
        url += f"&{key}={value}"

    return url


def get_transactions(address):
    transactions_url = make_api_url("account", "txlist", address, startblock=0, endblock=99999999, page=1, offset=10000,
                                    sort="asc")
    response = get(transactions_url)
    data = response.json()["result"]

    fwriter = open('trans.txt', 'a')

    for tx in data:

        to = tx["to"]
        from_addr = tx["from"]
        value = int(tx["value"]) / ETHER_VALUE
        gas = int(tx["gasUsed"]) * int(tx["gasPrice"]) / ETHER_VALUE
        time = datetime.fromtimestamp(int(tx['timeStamp']))
        fwriter.write("----------------" + "\n")
        fwriter.write("To: " + to + "\n")
        fwriter.write("From: " + from_addr + "\n")
        fwriter.write("Value: " + "{0}\n".format(value))
        fwriter.write("Gas Cost: " + "{0}\n".format(gas))
        fwriter.write("Time: " + "{0}\n".format(time))
    fwriter.close()


# get_transactions(address='0x0708F87A089a91C65d48721Aa941084648562287')
# 0 0x41147D719E3D703EAd97E88B38d737Be5f047167
# whale 0x0708F87A089a91C65d48721Aa941084648562287
