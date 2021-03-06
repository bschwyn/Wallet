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
        #mnemonic words back to entropy0488b21e

    def test_mnemonic_to_seed(self): #pass
        # compare to https://iancoleman.io/bip39/#english
        test_wallet = TurtleWallet("test")
        words = "day satisfy soft alarm more avocado all federal fragile fine gasp lava"
        actual_seed = test_wallet.mnemonic_to_seed(words)
        expected_seed = "59585af43a0de12e867c0eb14535151f0f456ef53738ee25696d32626ba5fd2f9724914b97b62259dfc224944618389a048cfd4aa4c2d3fd7e184c0cadf45218"
        self.assertEqual(actual_seed, expected_seed)

    def test_mnemonic_words(self): #pass
        test_wallet = TurtleWallet("test")
        words = test_wallet.mnemonic_words('3817eb3902e8fc1fc19aa35c6ad980be')
        self.assertEqual(words, "day satisfy soft alarm more avocado all federal fragile fine gasp lava")


    def test_generate_entropy(self): #pass
        pass
        # create wallet, generate entropy
        test_wallet = TurtleWallet("test")
        b = test_wallet.generate_entropy(128)
        c = test_wallet.mnemonic_words(b)
        #print(b)
        #print(c)
        # compare to https://iancoleman.io/bip39/#english


    def test_uncompressed_public_key(self):
        a = TurtleWallet("test")
        private_key = "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD"
        public_key = a.uncompressed_public_key(private_key)
        expected_public_key = "04" + "F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A" + "07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB"
        expected_public_key = expected_public_key.lower()
        self.assertEqual(public_key, expected_public_key)




    def test_master_extended_private(self):
        #  from https://en.bitcoin.it/wiki/BIP_0032
        a = TurtleWallet("test")
        seed = "000102030405060708090a0b0c0d0e0f"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        expected_ext_priv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        b58_ext_priv = a.extended_master_private_key(private_key, chain_code, "private main")
        self.assertEqual(b58_ext_priv, expected_ext_priv)

        # note: if this passes, this means that the seed to private key & chain code also passes and is correct for use finding child keys
        # HOWEVER......... THIS DOESN"T WORK?!?!?

    def test_master_extended_public(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        a = TurtleWallet("test")
        seed = "000102030405060708090a0b0c0d0e0f"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        public_key = a.compressed_public_key(private_key)
        expected_ext_pub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        actual_ext_pub = a.extended_master_public_key(public_key, chain_code)
        self.assertEqual(expected_ext_pub, actual_ext_pub)


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


    def test_parent_fingerprint(self):
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        public_key = a.compressed_public_key(private_key)
        #Chain m, test vector
        expected_ext_priv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        actual_ext_priv = a.extended_master_private_key(private_key, chain_code, 'private main')
        self.assertEqual(expected_ext_priv, actual_ext_priv)

        fingerprint = a.fingerprint(public_key)
        #chain m/0 test vector 2
        # xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt
        # 0488ade4 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e 17668a0b
        expected_fingerprint = "bd16bee5"
        self.assertEqual(expected_fingerprint, fingerprint)


    def test_extended_m(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

        # master keys, "chain m"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        public_key = a.compressed_public_key(private_key)
        expected_ext_priv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        expected_ext_pub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        actual_ext_priv = a.extended_master_private_key(private_key, chain_code, 'private main')
        actual_ext_pub = a.extended_master_public_key(public_key, chain_code)
        self.assertEqual(expected_ext_priv, actual_ext_priv)
        self.assertEqual(expected_ext_pub, actual_ext_pub)


    # def test_extended_m_0_child_chain_code(self):
    #     #https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    #
    #     a = TurtleWallet("test")
    #     seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    #
    #     #master keys, "chain m"
    #     private_key, chain_code = a.master_private_key_and_chain_code(seed)
    #     child_private_key, child_chain_code = a.private_parent_key_to_private_child_key(private_key, chain_code, 0)
    #     expected_child_chain_code = "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
    #     self.assertEqual(child_chain_code, expected_child_chain_code)
    #
    #     # xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt
    #     # 0488ade4 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e 17668a0b
    #     # 0488b21e 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea 44183bfc
    #
    #     #error sources --- seems easiest to make sure that I have the child chain code first:
    #     #HMAC-SHA512   I = hmac.new(unhexlify(self.chain_code),msg=unhexlify(data),digestmod=sha512).digest()
    #     #         I_L, I_R = I[:32], I[32:]

    def test_extended_m_0_hardened_child_private_key(self):
        a = TurtleWallet("test")
        seed = "000102030405060708090a0b0c0d0e0f"

        #master keys, "chain m"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        child_private_key, child_chain_code = a.private_parent_key_to_private_child_key(private_key, chain_code, pow(2,31))
        expected_child_chain_code = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        expected_child_private_key = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"

        self.assertEqual(child_chain_code, expected_child_chain_code)
        self.assertEqual(child_private_key, expected_child_private_key)

        # 0488ade4 01 3442193e 80000000 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141 00edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea 0a794dec

    def test_extended_m_0_nonhardened_child_private_key(self):
        # Using the unhardened test vector #2 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

        # master keys, "chain m"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        # get expected values by parsing extended keys
        # 0488ade4 00 00000000 00000000 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689 00 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e 61e16479
        expected_chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
        epxected_private_key = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        _, _, _, _, expected_chain_code, expected_private_key, _ = a.parse_extended_key("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        # check to see that the master keys/codes are correct
        self.assertEqual(expected_chain_code, chain_code)
        self.assertEqual(epxected_private_key, private_key)

        # parse the child key
        # 0488ade4 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e 17668a0b
        child_private_key, child_chain_code = a.private_parent_key_to_private_child_key(private_key, chain_code,0)
        expected_child_chain_code = "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
        expected_child_private_key = "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"

        # check to see that child keys/codes are correct
        self.assertEqual(child_chain_code, expected_child_chain_code)
        self.assertEqual(child_private_key, expected_child_private_key)

    def test_neuter_key(self):
        private_key = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        expected_public_key = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        a = TurtleWallet("test")
        public_key = a.neuter_key(private_key)
        self.assertEqual(private_key, expected_public_key)

    def test_compress_key(self):
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        uncompressed_pubkey = a.uncompressed_public_key(private_key) #ok
        compressed_pubkey = a.compressed_public_key(private_key)
        compressed_pubkey2 = a.compress_pubkey(uncompressed_pubkey)
        self.assertEqual(compressed_pubkey, compressed_pubkey2)

    def test_decompress_key(self):
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        private_key, chain_code = a.master_private_key_and_chain_code(seed)
        uncompressed_pubkey = a.uncompressed_public_key(private_key) #ok
        compressed_pubkey = a.compressed_public_key(private_key)
        uncompressed_pubkey2 = a.decompress_pubkey(compressed_pubkey)
        self.assertEqual(uncompressed_pubkey2, uncompressed_pubkey)

    def test_pubkey_pair(self):
        a = TurtleWallet('t')
        x,y = a.pubkey_to_pair()

    def test_compressed_public_key_to_pair(self):
        a = TurtleWallet('t')
        a.compressed_pubkey_to_pair()


    def test_elliptic_curve_group_addition(self):
        a = TurtleWallet("tst")
        private_key_full = "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD"
        private_key1 = "1E99423A4ED27608A15A26160000000000000000000000000000000000000000"
        private_key2 = "A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD"
        public_key1 = a.uncompressed_public_key(private_key1)
        public_key2 = a.uncompressed_public_key(private_key2)
        x1,y1 = a.pubkey_to_pair(public_key1)
        x2,y2 = a.pubkey_to_pair(public_key2)
        x3, y3 = a.ECGroupOp(x1, y1, x2, y2)

        public_key_full = a.uncompressed_public_key(private_key_full)
        xf,yf = a.pubkey_to_pair(public_key_full)
        self.assertEqual(x3, xf)
        self.assertEqual(y3, yf)




    def test_nonharded_public_parent_to_public_child(self):
        # get the child pubkey
        # parent privkey --> parent_pubkey --> child_pubkey
        # compare to expected_child_pubkey (parsed from test vector)
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        parent_private_key, parent_chain_code = a.master_private_key_and_chain_code(seed)
        parent_pubkey = a.compressed_public_key(parent_private_key)
        ext_parent_pubkey = a.extended_master_public_key(parent_pubkey, parent_chain_code)
        expected_ext_parent_pubkey = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        self.assertEqual(ext_parent_pubkey, expected_ext_parent_pubkey) #ok

        child_pubkey = a.public_parent_key_to_public_child_key(parent_pubkey, parent_chain_code,0)
        # 0488b21e 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea 44183bfc
        expected_child_pubkey = "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
        self.assertEqual(child_pubkey, expected_child_pubkey)



    def test_private_parent_key_to_public_child_key_nonhardened(self):
        # Using the unhardened test vector #2 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        a = TurtleWallet("test")
        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"


        # PATH 1 N(ckd_priv(parent_private_key))
        # master keys, "chain m"
        parent_private_key, parent_chain_code = a.master_private_key_and_chain_code(seed)
        child_private_key, child_chain_code = a.private_parent_key_to_private_child_key(parent_private_key, parent_chain_code, 0)
        expected_child_private_key = "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
        self.assertEqual(child_private_key, expected_child_private_key) #ok

        extended_child_private_key = a.private_parent_key_to_extended_private_child_key(parent_private_key, parent_chain_code, 0, 0, 0)
        # 0488ade4 01 4ff08c40 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e adefd67a
        # 0488ade4 01 bd16bee5 00000000 f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c 00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e 17668a0b
        expected_extended_child_private_key = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        self.assertEqual(extended_child_private_key, expected_extended_child_private_key)

        extended_child_public_key = a.neuter_key(extended_child_private_key)
        expected_extended_child_public_key = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        self.assertEqual(extended_child_public_key, expected_extended_child_public_key)

        # Path 2
        extended_parent_private_key = a.extended_master_private_key(parent_private_key, parent_chain_code, "private main")
        extended_parent_public_key = a.neuter_key(extended_parent_private_key)
        expected_extended_parent_public_key = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        self.assertEqual(extended_parent_public_key, expected_extended_parent_public_key)

        _, _, _, _, parent_chain_code_again, parent_public_key_again, _ = a.parse_extended_key(extended_parent_public_key)

        extended_child_public_key2 = a.public_parent_key_to_public_child_key(parent_public_key_again, parent_chain_code_again, 0)
        self.assertEqual(extended_child_public_key2, expected_extended_child_public_key)

        # get expected values by parsing extended keys
        # 0488ade4 00 00000000 00000000 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689 00 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e 61e16479
        #expected_chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
        #epxected_private_key = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        #_, _, _, _, expected_chain_code, expected_private_key, _ = a.parse_extended_key(
        #    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        # check to see that the master keys/codes are correct
        #self.assertEqual(expected_chain_code, chain_code)
        #self.assertEqual(epxected_private_key, private_key)
        pass






    def test_child_keys(self):
        pass
        # a = TurtleWallet("test")
        # seed = "000102030405060708090a0b0c0d0e0f"
        # private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
        # print("chain code:", chain_code)
        # print("private_key:", private_key)
        # public_key = a.generate_public_key_from_private_key(private_key)
        # #print('public_key:', public_key)
        # child_public_key12 = a.generate_public_key_from_private_key(child_private_key1)
        # self.assertEqual(child_public_key12, child_public_key1)
        # self.assertEqual(child_chain12, child_chain1)


    def test_transaction(self):
        pass
        # from_address = "0x029f7dd8f79fC19252Cb0cEb9c2021C727ae7074"
        # private_key = '6016f5822a0ea8f33a5e44444121e0e38c0d0748dc3188eba2ba301ac9978973'
        # wallet = TurtleWallet("test")
        # wallet.connect("ropsten")
        #
        # # balance of source before transaction
        # print(f"current balance: {w3.fromWei(wallet.connection.eth.getBalance(from_address), 'ether')} ether")
        # print(f"transaction count: {wallet.connection.eth.getTransactionCount(from_address)}")
        #
        # # send transaction
        # tx_hash = wallet.send_transaction(to_address="0x461254d3C61d1Af7DE6EBfF99f0e0D1040Aa9d8a",
        #                                 value=w3.toWei(1, "ether"))
        # wallet.wait_for_transaction(tx_hash)

        # balance of source after transaction
        print(f"current balance: {w3.fromWei(wallet.connection.eth.getBalance(from_address), 'ether')} ether")

    def test_transaction(self):
        pass
        # wallet = TurtleWallet("contains_test_eth") #I generated these mnemonic words with the wallet generator, but I don't think
        # # that means that this would necessarily be the same (as...)
        # words = "knife evoke duty acoustic artefact tumble bring diary valid couch motor gloom"
        # seed = ....
        # private_key, public_key, chain_code = wallet....
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
    #     # send transactionhahaha I grew up near Silverwood. I heard the name Cork
    #     tx_hash = wallet.send_transaction(to_address="0x2C3658828031133dfDE4e7daEE709ed2709fCaB1",
    #                                       value=w3.toWei(1, "ether"))
    #     wallet.wait_for_transaction(tx_hash)
    #
    #     #verify through ganache gui



if __name__ == '__main__':
    unittest.main()