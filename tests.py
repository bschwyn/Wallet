import sys
import unittest
from main import TurtleWallet
from frog import FrogWallet

from web3.auto.infura import w3

# a lot of the tests here reference: https://iancoleman.io/bip39/
# may want to get test vectors from here: https://en.bitcoin.it/wiki/BIP_0032

class TestStringMethods(unittest.TestCase):


    #def test_seed_to_mnemonic_and_back(self):
       # test_wallet= TurtleWallet("test")
       # entropy = test_wallet.generate_entropy(128)
       # mnemonic_words = test_wallet.mnemonic_words(entropy)
        #mnemonic words back to entropy

    def test_mnemonic_to_seed(self): #pass
        test_wallet = TurtleWallet("test")
        words = "day satisfy soft alarm more avocado all federal fragile fine gasp lava"
        seed = test_wallet.mnemonic_to_seed(words)
        self.assertEqual(seed,
                         "59585af43a0de12e867c0eb14535151f0f456ef53738ee25696d32626ba5fd2f9724914b97b62259dfc224944618389a048cfd4aa4c2d3fd7e184c0cadf45218")

    def test_mnemonic_words(self): #pass
        test_wallet = TurtleWallet("test")
        words = test_wallet.mnemonic_words('3817eb3902e8fc1fc19aa35c6ad980be')
        self.assertEqual(words, "day satisfy soft alarm more avocado all federal fragile fine gasp lava")


    def test_Turtle3(self): #pass
        pass
        # create wallet, generate entropy
        test_wallet = TurtleWallet("test")
        b = test_wallet.generate_entropy(128)
        c = test_wallet.mnemonic_words(b)
        #print(b)
        #print(c)
        # compare to https://iancoleman.io/bip39/#english

    def test_Turtle4(self): #fail
        a = TurtleWallet("test")
        words = "day satisfy soft alarm more avocado all federal fragile fine gasp lava"
        private_key, public_key, chain_code = a.generate_master_keys_and_codes(words)
        #extended_public_key = public_key + chain_code
        #print()
        #print(
        #    extended_public_key == 'xpub6BkTcpit577MTiPmqQ8q9XKJBJvra4WbBb6ioi1UHAMyUj8fNeJPPzjGKdQJqhyeKw4jEJZotv6Q9fYYVAPMGCLi8NRDkGvyDhkqNosZe6X')
        #print(private_key == 'asdf')

    # def test_extended(self):
    #     a = TurtleWallet("test")
    #     # private
    #     seed = "59585af43a0de12e867c0eb14535151f0f456ef53738ee25696d32626ba5fd2f9724914b97b62259dfc224944618389a048cfd4aa4c2d3fd7e184c0cadf45218"
    #     private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
    #     extended_key_expected_hex = '0488ade40146886a8400000000738e0ba1970a09deb365c2e5e583ec0d787977f6a30e67a7e96fa42d5a983af4002b8b9cfa3dd327ce9bae448d0a31254cc0568181bbf7dca9b59ec2e7adf042bdedabacad'
    #     # base58 encoded
    #     extended_key_b58_expected = 'xprv9uRDRSEAyyjruNH6xr9ssR6vxH1kfe8V3HSMmVf9febopzRSNWArjWBwNdHCTxp2yBTqWgkE8rGbMR5PyXbBp5gKx5291C9Tn8C3CPFpPyn'
    #     extended, extended_key_b58_actual = a.extended_master_private_key(private_key, chain_code, 'private main')
    #     print(extended_key_b58_actual)
    #     print(extended)

    def test_extended(self):
        #  from https://en.bitcoin.it/wiki/BIP_0032
        a = TurtleWallet("test")
        seed = "000102030405060708090a0b0c0d0e0f"
        private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
        expected_ext_priv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        ext_priv, b58_ext_priv = a.extended_master_private_key(private_key, chain_code, 'private main')
        self.assertEqual(b58_ext_priv, expected_ext_priv)
        print(b58_ext_priv)

    def test_address_from_public_key(self):
        a = TurtleWallet("test")

        #another example https://hackernoon.com/how-to-generate-ethereum-addresses-technical-address-generation-explanation-25r3zqo
        public_key = "048e66b3e549818ea2cb354fb70749f6c8de8fa484f7530fc447d5fe80a1c424e4f5ae648d648c980ae7095d1efad87161d83886ca4b6c498ac22a93da5099014a"
        address = a.generate_address_from_public_key(public_key)
        expected_address = "00b54e93ee2eba3086a55f4249873e291d1ab06c"
        self.assertEqual(address, expected_address)

        #from Mastering Ethereum
        public_key = "046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0"
        address = a.generate_address_from_public_key(public_key)
        expected_address = "001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
        self.assertEqual(address, expected_address)

    def test_transaction(self):
        pass
        # wallet = TurtleWallet("contains_test_eth") #I generated these mnemonic words with the wallet generator, but I don't think
        # # that means that this would necessarily be the same (as...)
        # words = "knife evoke duty acoustic artefact tumble bring diary valid couch motor gloom"
        # private_key, public_key, chain_code = wallet.generate_master_keys_and_codes(words)
        #
        # # balance of source before transaction
        # print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")
        # print(f"transaction count: {connection.eth.getTransactionCount(from_address)}")
        # #
        # # send transaction
        # tx_hash = wallet.send_transaction(to_address="0x461254d3C61d1Af7DE6EBfF99f0e0D1040Aa9d8a", value=w3.toWei(1, "ether"))
        # wallet.wait_for_transaction(tx_hash)
        #
        # # balance of source after transaction
        # print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")


"""
    def test_master_private_key(self):
        a = TurtleWallet('test')
        # words for this seed: 'day satisfy soft alarm more avocado all federal fragile fine gasp lava'
        # assumming https://iancoleman.io/bip39/ is correct
        seed = "59585af43a0de12e867c0eb14535151f0f456ef53738ee25696d32626ba5fd2f9724914b97b62259dfc224944618389a048cfd4aa4c2d3fd7e184c0cadf45218"
        private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)

        # expected according to https://iancoleman.io/bip39/
        expected_bip32_root_key = 'xprv9s21ZrQH143K3TxHvWQB7XYt9wGZ4FVAo3WAjGSR9Dd9uFai7zXH42v96YUeiV7677jvj5w3Yq2kukFoY5QeFu2DvxsEq9zDGJSDUTswkMT'
        # de-encoding with https://www.better-converter.com/Encoders-Decoders/Base58Check-to-Hexadecimal-Decoder
        expected_bip32_root_key_hex = '0488ade40000000000000000008d4e40e5dfbdef4f4147f824206c5dbd0e222ea87c8fc92a94a115ae3f42fe2100b2c49252290b6bc494704106bd9815e3a0e0306e101ac97e0274eaa3c3d46c988484a33e'
        root_key_hex = 'b2c49252290b6bc494704106bd9815e3a0e0306e101ac97e0274eaa3c3d46c988484a33e'

        print(private_key)
        print(chain_code)
        extended_private_key, encoded_private_key = a.extended_master_private_key(private_key, chain_code,
                                                                                  "private main")
"""

# would be cool to have something to turn these tests on and off

# class TestNetworksAndTransactions(unittest.TestCase):
#     def test_Frog(self):
#         frog = FrogWallet()
#         # connection, chain_id = connect("kovan")
#         connection, chain_id = frog.connect("ropsten")
#         from_address = "0x029f7dd8f79fC19252Cb0cEb9c2021C727ae7074"
#         private_key = '6016f5822a0ea8f33a5e44444121e0e38c0d0748dc3188eba2ba301ac9978973'
#         wallet = FrogWallet(from_address, private_key)
#
#         # balance of source before transaction
#         print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")
#         print(f"transaction count: {connection.eth.getTransactionCount(from_address)}")
#
#         # send transaction
#         tx_hash = wallet.send_transaction(to_address="0x461254d3C61d1Af7DE6EBfF99f0e0D1040Aa9d8a",
#                                           value=w3.toWei(1, "ether"))
#         wallet.wait_for_transaction(tx_hash)
#
#         # balance of source after transaction
#         print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")

    #
    # def test_ganache(self):
    #
    #     print('hello')
    #     from_address = "0xf67643d49Ea9d68413D8d74717Da09E235b7D01d"
    #     private_key = '6e82f0bf30100c06597ccb7edab90c8c8a02d03c80883466dfc97e5cb8b6cd4a'
    #     wallet = FrogWallet(from_address, private_key, "ganache")
    #
    #     # send transaction
    #     tx_hash = wallet.send_transaction(to_address="0x2C3658828031133dfDE4e7daEE709ed2709fCaB1",
    #                                       value=w3.toWei(1, "ether"))
    #     wallet.wait_for_transaction(tx_hash)
    #
    #     #verify through ganache gui



if __name__ == '__main__':
    unittest.main()