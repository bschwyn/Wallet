# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

"""
What is a wallet?
- stores and manages keys
- stores private keys in encrypted form
- private key (number, picked at random)--->

Generate private key:
- 256 bit number
random bits ---> SHA-256, retry if not valid
- can be encoded in binary, base 10, hexidecimal format

Generate public key:
- w/ elliptic curve math, generate x,y values and concatenate them
- openSSL or libsecp256k1

All Wallets:
- have at least one key

FrogWallet
- provided key and associated account (not necessarily

NewtWallet
- provided key, generates account
- if account is generated via correct cryptography, it should be the same as the account associated w/ the key in metamask

TurtleWallet
- provided Mnemonic Words, generates key, generates account

SnakeWallet
- Hierarchially deterministic wallet / master key / seed generates wallets

Considerations:
- private key / account backup - append to a list stored locally?
- print them out and say "write these down in a secure location"


#TODO
- find standard encodings
    - does hex start with '0x' or not?
        - no '0x' when possible: 'deadbeef'
    - should everything take a hex string and output hex string?
- add types to function strings
- add extended public, private keys, serialization for this
- add child key generation for depth 1
- test CLI - new wallet generation
    - addition of new wallets
    - use of wallets for transactions
- save JSON of wallets to text file
- list wallets in JSON file

Bugs
- how to do base58 encoding? the encoding in the book is 00-->1, 05-->3, 6f--->m or n, whereas this website
https://www.appdevtools.com/base58-encoder-decoder does these encodings:
00--->1
05--->6
6f--->2v
0488b21e---71isbb
now that's weird.

Glossary:
Entropy: random number from system of 128 bits (16 bytes) / 32 hex characters
mnemonic words: entropy + checksum ---> 12 associated words
seed: hashing of mnemonic words + salt + passphrase ---> 512 (64 byte)/128 hex chars seed
master private key: left side of hash of seed
master chain code: right side of hash of seed
master public key: elliptic curve output (x+y) derived from master private key
extended master private key:  master private key + chain code + index + network and other info in base58check. Can be
    used to derive a full branch.
extended master public key: master private key + chain code + index + network and other info in base58check. Can be only
    used to dervice a branch of public keys.
address: derived from public key via hash, encoded in base58check

Standards:
- return values in hex when possible
- hex as strings with no '0x' prefix, e.g. "deadbeef"


"""
#i dunno why this needs to be here
import os
os.environ["WEB3_INFURA_PROJECT_ID"] = "afc8c9407f364433880c670ec94b3534"

import hashlib
import hmac

import json
import random

import base58
from Crypto.Hash import keccak
from web3 import Web3
from web3.auto.infura import w3
#from frog import NewtWallet
from elliptic import EllipticCurveMath

class TurtleWallet:
    #takes entropy and generates mnemonic code words according to BIP39
    #takes code words to generate private key / address
    """
    This implements an HD wallet. HD wallets have a tree structure starting with 1 root key pair. That pair can have X
    chldren, and each child can have many children. While new keys could be constructed off of the grandchildren of the
    root, this implementation only makes new children. It also does not list the master address, it when list addresses
    is called, all of the indexed children of the master are returned.


    """

    def __init__(self, name):
        self.wallet_name = name
        self.entropy_len = 128 ### needs to be set more appropriately later
        pass

    @classmethod
    def build_wallet(cls, dictionary):
        wallet = TurtleWallet(dictionary['name'])
        wallet.master_private_key = dictionary['info']['master_private_key']
        wallet.master_public_key = dictionary['info']['master_public_key']
        return wallet

    def generate_entropy(self, n_bits):
        # int ----> hex_string, e.g. "deadbeef"
        self.entropy_len = n_bits
        # returns n_bits of entropy in a hex string
        # SECURITY ERROR --- need to switch this to "SecureRandom"
        entropysource = random.getrandbits(n_bits) #integer, base 10
        entropysource_hex = hex(entropysource)[2:] #str of hex char
        #extra zeros since sometimes getrandbits gives number with fewer digits
        #to ensure entropy is 128 bits /home/bschwynand leadign zero bits are included
        entropysource_hex = '0'*(32-len(entropysource_hex)) + entropysource_hex
        return entropysource_hex

    def mnemonic_words(self, entropy):
        #expecting an entropy of a hexstring: e.g. entropy = "deadbeef"

        hash_obj = hashlib.sha256(bytes.fromhex(entropy)) #SOMETIMES gives error, but not always?
        # ValueError: non-hexadecimal number found in fromhex() arg at position 31
        checksum = hash_obj.hexdigest()[0] #str of hex char
        hex_str = str(entropy) + checksum

        #hex string to binary words
        binary = bin(int(hex_str, 16))[2:]  # convert to binary and remove '0b'
        bit_arr = binary.zfill(self.entropy_len + 4)
        segments = [bit_arr[i:i + 11] for i in range(0, self.entropy_len + 4, 11)]

        # binary words to mnemonic words
        with open("wordlist.txt") as text:
            bip39 = text.read().splitlines()
        mnemonic = " ".join([bip39[int(bits, 2)] for bits in segments])
        return mnemonic

    def mnemonic_to_seed(self, mnemonic, optional_passphrase=""):
        salt = "mnemonic" + optional_passphrase
        hash_str = hashlib.pbkdf2_hmac("sha512", mnemonic.encode('utf-8'), salt.encode('utf-8'), 2048)
        seed = hash_str.hex()
        return seed

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

    def generate_master_keys_and_codes(self, seed):
        hash_bytes = hmac.new(b"Bitcoin seed", bytes.fromhex(seed), hashlib.sha512).digest()
        left = hash_bytes[:32]  # 32 since hmac returns bytes
        right = hash_bytes[32:]
        master_private_key = left.hex()
        master_chain_code = right.hex()
        master_public_key = self.generate_public_key(int(master_private_key, 16)) ### maybe change this so it accepts hex strings, rather than integers
        return master_private_key, master_public_key, master_chain_code

    def generate_master_private_key_and_chain_code(self, seed):
        hash_bytes = hmac.new(b"Bitcoin seed", bytes.fromhex(seed), hashlib.sha512).digest()
        left = hash_bytes[:32] #32 since hmac returns bytes
        right = hash_bytes[32:]
        master_private_key = left.hex()
        master_chain_code = right.hex()
        return master_private_key, master_chain_code


    def generate_address(self, public_key):
        #TOTALLY WRONG???
        k = keccak.new(digest_bits=256)
        print('generating address from: ', public_key)
        public_key_string = str(public_key)
        k.update(bytes(public_key_string, 'utf-8'))
        hashed_key = k.hexdigest()
        address = hashed_key[-20:] #last 20 digits
        return address

    def list_addresses(self):
        #get master public address
        # does it make sense to store the tree shape but not the values?
        #addressess are created in order, with a max number of children for each row
        pass


    def generate_address_from_private_key(self, private_key):
        public_key = self.generate_public_key_from_private_key(int(private_key,16))
        address = self.generate_address(public_key)
        return address

    def extended_master_private_key(self, private_key, chain_code, network):
#0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
        version = {'public main': '0488b21e',
                         'private main': '0488ade4',
                         'public test': '043587cf',
                         'private test': '04358394'}

        version_bytes = version[network]
        depth = '00' # master
        parent_fingerpint = '00000000' #hex
        child_number = '00000000' #hex
        chain_code = chain_code
        private_key = '00' + private_key #should start with 0x02 or 0x03
        extended = version_bytes + depth + parent_fingerpint + child_number + chain_code + private_key

        hash1 = hashlib.sha256(bytes.fromhex(extended)).hexdigest()
        hash2 = hashlib.sha256(hash1.encode('utf-8')).hexdigest()
        checksum = hash2[:8]

        encoded_string = base58.b58encode(bytes.fromhex(extended + checksum))
        return extended, encoded_string

    def extended_key(self, public, network, depth, index, key, parent='', chain_code=''):
        version = {'public main': '0488b21e',
                   'private main': '0488ade4',
                   'public test': '043587cf',
                   'private test': '04358394'}

        version = {'public':{'main': '0488b21e', 'test': '043587cf'},
                   'private': {'main': '0488ade4', 'test': '04358394'}}

        version_bytes = version[public][network]
        #depth
        depth = hex(depth)[2:]
        if len(depth) == 1:
            depth = '0' + depth
        elif len(depth) > 2:
            raise ValueError

        if not parent:
            parent_fingerpint = '00000000'  # hex
        else:
            parent_fingerprint = parent[:8]
        child_number = hex(index)[:2]  # hex
        chain_code = chain_code
        if not public:
            key = '00' + key
        extended = version_bytes + depth + parent_fingerpint + child_number + chain_code + key

        hash1 = hashlib.sha256(bytes.fromhex(extended)).hexdigest()
        hash2 = hashlib.sha256(hash1.encode('utf-8')).hexdigest()
        checksum = hash2[:8]

        encoded_string = base58.b58encode(bytes.fromhex(extended + checksum))
        return extended, encoded_string

    def extended_master_public_key(self, public_key, chain_code):
        version_bytes = '2323a043587CF' # public testnet
        depth = '00' #for master, 1 for level-1 derived...
        parent_fingerprint = '00000000'
        child_number = '00000000'
        chain_code = chain_code
        public_key = public_key

        extended = version_bytes + depth + parent_fingerprint + child_number + chain_code + public_key

        hash1 = hashlib.sha256(bytes.fromhex(extended)).hexdigest()
        hash2 = hashlib.sha256(hash1.encode('utf-8')).hexdigest()

        # convert to base 58

        encoded_string = base58.b58encode(bytes.fromhex(extended + hash2))
        # THIS IS INCORRECT
        return encoded_string


    def generate_new_child_private_key(self, index, parent_private_key, parent_chain_code):
        # wouldn't want to give the wrong chain code with the private key --- is there any way to check that these are associated?
        hash_str = parent_private_key + parent_chain_code + index
        hashlib.sha512(hash_str.encode('utf-8'))

    def generate_new_child_public_key(self):
        pass


    # transaction
    def send_transaction(self, private_key, to_address, value):
        #add: gas strategy

        from_address = self.generate_address_from_private_key(private_key) #assuming private key in hex

        transaction = {
            'from': from_address,
            'to': to_address,
            'value': value,
            'gas': 1000000,
            'gasPrice': w3.toWei('150','gwei'),
            'nonce': self.connection.eth.getTransactionCount(from_address),
            'chainId': self.chain_id
        }
        #private_key = os.environ['PRIVATE_KEY']
        signed_transaction = self.connection.eth.account.sign_transaction(transaction, private_key)
        tx_hash = self.connection.eth.sendRawTransaction(signed_transaction.rawTransaction)
        return tx_hash

    def wait_for_transaction(self, tx_hash):
        receipt = self.connection.eth.wait_for_transaction_receipt(tx_hash)  # timeout here
        print(receipt)


def new_wallet(name):
    new_wallet = TurtleWallet(name)
    entropy = new_wallet.generate_entropy(128)
    mnemonic_words = new_wallet.mnemonic_words(entropy)
    print("Write down your mnemonic words (in order) and store them in safe place.")
    print("If you lose them, you may not be able to recover the wallet and associated funds")
    print("mnemonic_words: ", mnemonic_words)
    while True:
        print("Press 'y' to continue")
        continue_ = input()
        if continue_ == "y":
            break
    seed = new_wallet.mnemonic_to_seed(mnemonic_words)
    private_key, public_key, chain_code = new_wallet.generate_master_keys_and_codes(seed)
    #public_key0 = new_wallet.generate_child_public_key(parent_public_key, chain_code, index=0)
    #private_key0 = new_wallet.generate_child_private_key(parent_private_key, chain_code, index=0)

    wallet_info = {"name": name, "info": {"master_private_key": private_key, "master_public_key": public_key, "children": 1}}
    # serialize
    #save to json file

    with open('data.json', 'w') as f:
        json.dump(wallet_info, f)

def access_wallet_json(name):
    # search json
    data = []
    with open('data.json') as f:
        for line in f:
            data.append(json.loads(line))
    #search data
    for json_wallet in data:
        #json_wallet = json.loads(line)
        if name == json_wallet['name']:
            #found
            return json_wallet
    return []

def access_wallet(name):
    #get wallet from json
    wallet_dict = access_wallet_json(name)
    if not wallet_dict:
        return None
    #constuct wallet
    wallet = TurtleWallet.build_wallet(wallet_dict)
    return wallet



    def test_Frog():


        # connection, chain_id = connect("kovan")
        connection, chain_id = frog.connect("ropsten")

        from_address = "0x029f7dd8f79fC19252Cb0cEb9c2021C727ae7074"
        private_key = '6016f5822a0ea8f33a5e44444121e0e38c0d0748dc3188eba2ba301ac9978973'
        frog = FrogWallet(from_address, private_key, "ropsten")


        # balance of source before transaction
        print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")
        print(f"transaction count: {connection.eth.getTransactionCount(from_address)}")

        # send transaction
        tx_hash = wallet.send_transaction(to_address="0x461254d3C61d1Af7DE6EBfF99f0e0D1040Aa9d8a",
                                          value=w3.toWei(1, "ether"))
        wallet.wait_for_transaction(tx_hash)

        # balance of source after transaction
        print(f"current balance: {w3.fromWei(connection.eth.getBalance(from_address), 'ether')} ether")


def test_extended():
    a = TurtleWallet("test")
        # private
    seed = "59585af43a0de12e867c0eb14535151f0f456ef53738ee25696d32626ba5fd2f9724914b97b62259dfc224944618389a048cfd4aa4c2d3fd7e184c0cadf45218"
    private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
    extended_key_expected_hex = '0488ade40146886a8400000000738e0ba1970a09deb365c2e5e583ec0d787977f6a30e67a7e96fa42d5a983af4002b8b9cfa3dd327ce9bae448d0a31254cc0568181bbf7dca9b59ec2e7adf042bdedabacad'

        # base58 encoded
    extended_key_b58_expected = 'xprv9uRDRSEAyyjruNH6xr9ssR6vxH1kfe8V3HSMmVf9febopzRSNWArjWBwNdHCTxp2yBTqWgkE8rGbMR5PyXbBp5gKx5291C9Tn8C3CPFpPyn'
    extended, extended_key_b58_actual = a.extended_master_private_key(private_key, chain_code, 'private main')
    print(extended_key_b58_actual)
    print(extended)

def test_seed_to_mnemonic_and_back():
    test_wallet= TurtleWallet("test")
    seed = test_wallet.generate_entropy(128)
    print(seed)
    mnemonic_words = test_wallet.mnemonic_words(seed)
    seed2 = test_wallet.mnemonic_to_seed(mnemonic_words)
    print(seed2)
    #self.assertEqual(seed, seed2)


if __name__ == '__main__':
    test_seed_to_mnemonic_and_back()
    #test_master_private_key()