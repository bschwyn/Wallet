

import hashlib
import json
import os
import random

from Crypto.Hash import keccak
from web3 import Web3
from web3.auto.infura import w3
from elliptic import EllipticCurveMath

def connect(network):
    if network == "kovan":
        infura_kovan_url = "https://kovan.infura.io/v3/afc8c9407f364433880c670ec94b3534"
        web3 = Web3(Web3.HTTPProvider(infura_kovan_url))
        chain_id = 42
        print("connected to kovan network:", web3.isConnected())
    elif network == "ropsten":
        infura_ropsten_url = "https://ropsten.infura.io/v3/afc8c9407f364433880c670ec94b3534"
        web3 = Web3(Web3.HTTPProvider(infura_ropsten_url))
        chain_id = 3
        print("connected to ropsten network:", web3.isConnected())
    elif network =="ganache":
        ganache_url = "http://localhost:7545"
        web3 = Web3(Web3.HTTPProvider(ganache_url))
        chain_id = 1337
    return web3, chain_id


class FrogWallet:

    def __init__(self, from_address, private_key, network):
        self.from_address = from_address
        self.private_key = private_key
        self.connection, chain_id = connect(network)
        self.chain_id = chain_id

    def send_transaction(self, to_address, value):
        #add: gas strategy

        transaction = {
            'from': self.from_address,
            'to': to_address,
            'value': value,
            'gas': 1000000,
            'gasPrice': w3.toWei('150','gwei'),
            'nonce': self.connection.eth.getTransactionCount(self.from_address),
            'chainId': self.chain_id
        }
        #private_key = os.environ['PRIVATE_KEY']
        signed_transaction = self.connection.eth.account.sign_transaction(transaction, self.private_key)
        tx_hash = self.connection.eth.sendRawTransaction(signed_transaction.rawTransaction)
        return tx_hash

    def wait_for_transaction(self, tx_hash):
        receipt = self.connection.eth.wait_for_transaction_receipt(tx_hash)  # timeout here
        print(receipt)


class NewtWallet:

    def __init__(self, private_key_base_10): #private key should be in base 10
        # generate public key from from private_key
        self.private_key = private_key_base_10
        self.public_key = self.generate_public_key(self.private_key)
        self.address = self._generate_address()


    def generate_public_key(self, private_key):

        # curve configuration
        mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
        order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

        # curve configuration
        # y^2 = x^3 + a*x + b = x^3 + 7
        a = 0
        b = 7

        # base point on the curve
        x0 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        y0 = 32670510020758816978083085130507043184471273380659243275938904335757337482424

        print("---------------------")
        print("initial configuration")
        print("---------------------")
        print("Curve: y^2 = x^3 + ", a, "*x + ", b)
        print("Base point: (", x0, ", ", y0, ")\n")
        print("modulo: ", mod)
        print("order of group: ", order)

        # print("private key: ", privateKey)
        print("private key (hex): ", hex(private_key)[2:], " (keep this secret!)\n")

        ecdsa = EllipticCurveMath()

        public_key = ecdsa.applyDoubleAndAddMethod(x0, y0, private_key, a, b, mod)
        # print("public key: ", publicKey)

        public_key_hex = "04" + hex(public_key[0])[2:] + hex(public_key[1])[2:]
        print("public key (hex): ", public_key_hex)

        return public_key_hex


    def _generate_address(self):
        k = keccak.new(digest_bits=256)
        print('generatign addrss from: ', self.public_key)
        public_key_string = str(self.public_key)
        k.update(bytes(public_key_string, 'utf-8'))
        hashed_key = k.hexdigest()
        self.address = hashed_key[-20:]
