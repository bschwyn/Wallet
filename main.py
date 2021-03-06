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
    - use of wallets for transactions

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
- public keys possibilities:
    - (int, int)
    - (hex, hex)
    - hexbytes, hexbytes
    - uncompressed key
    - compressed key
    - extended key

Public key class?
Extended public key class is an instance of a public key class

Private Key
- int
- hex
- bytes
- extended
Extended Privkey is an instance of private key

Everytime you call a value, specify what the format is?


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
import frog
from elliptic import EllipticCurveMath

class TurtleWallet:
    #takes entropy and generates mnemonic code words according to BIP39
    #takes code words to generate private key / address
    """
    This implements an HD wallet. HD wallets have a tree structure starting with 1 root key pair. That pair can have X
    chldren, and each child can have many children. While new keys could be constructed off of the grandchildren of the
    root, this implementation only makes new children. It also does not list the master address, it when list addresses
    is called, all of the indexed children of the master are returned.

    Mnemonic Code Words: BIP-39
    HD wallet: BIP-32. ?implemented totally????
    """

    def __init__(self, name):
        self.wallet_name = name
        self.entropy_len = 128 ### needs to be set more appropriately later
        # not sure which of these things should be saved or how (for security)
        # but making a list anyways for now
        self.network = None
        self.seed = None
        self.mnemonic_words
        self.private_key = None
        self.public_key = None
        self.extended_master_None_key = None
        #self.extended_master_public_key = None

    def connect(self, network):
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
        elif network == "ganache":
            ganache_url = "http://localhost:7545"
            web3 = Web3(Web3.HTTPProvider(ganache_url))
            chain_id = 1337
        self.connection = web3
        self.chain_id = chain_id
        return web3, chain_id

    @classmethod
    def build_wallet(cls, dictionary):
        wallet = TurtleWallet(dictionary['name'])
        wallet.master_private_key = dictionary['info']['master_private_key']
        wallet.master_public_key = dictionary['info']['master_public_key']
        return wallet

    #seed generation

    def generate_entropy(self, n_bits):
        """
        generates a hex string of entropy with n bits
        :param n_bits (int):
        :return: hexstring, e.g. "deadbeef"
        """
        self.entropy_len = n_bits
        # SECURITY ERROR --- need to switch this to "SecureRandom"
        entropysource = random.getrandbits(n_bits) #integer, base 10
        entropysource_hex = hex(entropysource)[2:] #str of hex char
        #extra zeros since sometimes getrandbits gives number with fewer digits
        #to ensure entropy is 128 bits /home/bschwynand leadign zero bits are included
        entropysource_hex = '0'*(32-len(entropysource_hex)) + entropysource_hex
        return entropysource_hex

    def mnemonic_words(self, entropy):
        """
        generates a set of mnemonic words from a hexstring (e.g. "deadbeef")
        :param entropy:
        :return string of words separated by spaces:
        """

        hash_obj = hashlib.sha256(bytes.fromhex(entropy)) #SOMETIMES gives error, but not always?   #see test4
        # ValueError: non-hexadecimal number found in fromhex() arg at position 31 #Test4
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

    # * * * key generation from seed or key * * *

    def public_key_pair(self, private_key):
        #hex ----> int pair

        # convert hex to int
        private_key = int(private_key, 16)

        # curve confiKi is point(parse256(IL)) + Kpar.guration
        mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
        #order = 115792089237316195423570985008687907852837564279074904382605163141518161494337 #look up where this comes from
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

        # curve configuration
        # y^2 = x^3 + a*x + b = x^3 + 7
        a = 0
        b = 7

        # base point on the curve
        x0 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        y0 = 32670510020758816978083085130507043184471273380659243275938904335757337482424

        # initial configuration
        # print("Curve: y^2 = x^3 + ", a, "*x + ", b)
        # print("Base point: (", x0, ", ", y0, ")\n")
        # print("modulo: ", mod)
        # print("order of group: ", order)

        # print("private key: ", privateKey)
        # print("private key (hex): ", hex(private_key)[2:], " (keep this secret!)\n")

        ecdsa = EllipticCurveMath()

        public_key = ecdsa.applyDoubleAndAddMethod(x0, y0, private_key, a, b, mod)
        return public_key


    def uncompressed_public_key(self, private_key):
        public_key_pair = self.public_key_pair(private_key)
        prefix = "04"
        x = hex(public_key_pair[0])[2:].zfill(64)
        y = hex(public_key_pair[1])[2:].zfill(64)
        public_key_hex = prefix + x + y
        return public_key_hex

    def decompress_pubkey(self, public_key):
        # this seems ?somewhat? difficult to do...
        # solve y^2 = x^3 + 7 for y...,
        # https://bitcoin.stackexchange.com/questions/86234/how-to-uncompress-a-public-key
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F #same as "Order". make this a constant?
        prefix = public_key[:2]
        x = int(public_key[2:66],16)
        y_sq = (pow(x,3, p) + 7) % p
        y = pow(y_sq, (p + 1) //4, p) #I don't understand this line. why (p+1)//4 instead 1//2?
        if y % 2 != int(prefix) % 2: # don't understand this either (why) (note int("02",16) == int("02")
            y = p-y  #or this
        decompressed_key = "04" + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64)
        return decompressed_key


    def pubkey_to_pair(self, uncompressed_public_key):
        # takes hex, returns int pair
        x_y =  uncompressed_public_key[2:]
        x = int(x_y[:64],16)
        y = int(x_y[64:], 16)
        return x, y


    def compressed_pubkey_to_pair(self, pubkey):
        decompressed = self.decompress_pubkey(pubkey)
        x,y = self.public_key_pair(decompressed)
        return x,y

    def ECGroupOp(self, x1, y1, x2, y2):
        # takes 2 public key pairs and "adds" them.
        # curve configuration
        mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
        #order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        # y^2 = x^3 + a*x + b = x^3 + 7
        a = 0
        b = 7
        ecdsa = EllipticCurveMath()
        x3, y3 = ecdsa.pointAddition(x1, y1, x2, y2, a, b, mod)
        return x3, y3

    def compress_pubkey(self, uncompressed_pubkey):
        #takes hex
        x = uncompressed_pubkey[2:66]
        y = uncompressed_pubkey[66:]
        prefix = "02" if int(y,16) % 2 == 0 else "03"
        compressed_public_key_hex = prefix + x
        return compressed_public_key_hex

    def compressed_public_key(self, private_key):
        public_key = self.public_key_pair(private_key)
        prefix = "02" if public_key[1] % 2 == 0 else "03"
        compressed_public_key_hex = prefix + hex(public_key[0])[2:]
        return compressed_public_key_hex

    def master_private_key_and_chain_code(self, seed):
        hash_bytes = hmac.new(b"Bitcoin seed", bytes.fromhex(seed), hashlib.sha512).digest()
        left, right = hash_bytes[:32], hash_bytes[32:]
        key, chain_code = left.hex(), right.hex()
        return key, chain_code

    def generate_master_keys_and_codes(self, master_seed):
        master_private_key, master_chain_code = self.master_private_key_and_chain_code(master_seed)
        master_public_key = self.uncompressed_public_key(master_private_key) ### maybe change this so it accepts hex strings, rather than integers
        return master_private_key, master_public_key, master_chain_code

    def fingerprint(self, public_key):
        hash1 = hashlib.sha256(bytes.fromhex(public_key)).digest()
        hash2 = hashlib.new('ripemd160', hash1).hexdigest()
        return hash2[:8]

    def int_to_8bit_hex(self, val):
        val = hex(val)[2:]
        return val.zfill(8)


    def extended_key(self, network, depth, index, key, parent_key, chain_code):
        version = {'public main': '0488b21e',
                   'private main': '0488ade4',
                   'public test': '043587cf',
                   'private test': '04358394'}

        version_bytes = version[network]
        # depth
        depth = hex(depth)[2:].zfill(2)
        if len(depth) > 2:
            raise ValueError

        #child_number = hex(index)[2:]  # hex
        #child_number = child_number.zfill(8)
        child_number = self.int_to_8bit_hex(index)
        chain_code = chain_code
        if "private" in network:
            # this should definitely change...fingerprint should always be of public key
            key = '00' + key
            parent_fingerprint = self.fingerprint(self.compressed_public_key(parent_key)) if parent_key else '00000000'
        else:
            parent_fingerprint = self.fingerprint(parent_key) if parent_key else '00000000'

        extended = version_bytes + depth + parent_fingerprint + child_number + chain_code + key

        hash1 = hashlib.sha256(bytes.fromhex(extended)).digest()
        hash2 = hashlib.sha256(hash1).hexdigest()
        checksum = hash2[:8]

        encoded_string = base58.b58encode(bytes.fromhex(extended + checksum)).decode('utf-8')
        return encoded_string

    def extended_master_private_key(self, private_key, chain_code, network):
        return self.extended_key(network="private main", depth=0, index=0, key=private_key, parent_key=None, chain_code=chain_code)

    def extended_master_public_key(self, public_key, chain_code):
        #public key needs to be compressed
        if (public_key[:2] != "02") and (public_key[:2] != "03"):
            raise ValueError
        return self.extended_key(network="public main", depth=0, index=0, key=public_key, parent_key=None, chain_code=chain_code)

    # * * * child generation * * *

    def private_parent_key_to_private_child_key(self, parent_private_key, parent_chain_code, child_index):
        """
        check whether i >= 2^31
            if so return I=HMAC-SHA512(Key=c_par, Data = 0x00 || ser_256(k_par) || ser_32(i)
            else I=HMAC-SHA512(key=c_par, Data=ser_p(point(k_par)) || ser_32(i))
        split I into two 32-bytes sequeces I_L and I_R
        the reutrned child key k_i is parse_256(I_L) + k_par(mod n)
        the returned child chain code is I_R
        if parse_256(I_L) >=n or k_i = 0, key is invalid
        """
        hardened = False
        if child_index >= pow(2,31):
            hardened = True
        child_index = hex(child_index)[2:].zfill(8)

        if hardened:
            data = "00" + parent_private_key + child_index
        else:
            public_key = self.compressed_public_key(parent_private_key)
            data = public_key + child_index

        hash_bytes = hmac.new(bytes.fromhex(parent_chain_code), bytes.fromhex(data), hashlib.sha512).digest()
        left, right = hash_bytes[:32], hash_bytes[32:]

        order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        child_private_key = int(left.hex(), 16) + int(parent_private_key,16) % order
        if child_private_key == 0 or int(left.hex(), 16) >= order:
            raise Error
        child_private_key_hex = hex(child_private_key)[2:]
        new_chain_code = right.hex()
        return child_private_key_hex, new_chain_code

    def private_parent_key_to_extended_private_child_key(self, parent_private_key, parent_chain_code, parent_index, parent_depth, child_index):
        # I could probably modify this so that it doesn't require the parent private key and chain code, but
        # relies just on the tree!
        child_private_key, chain_code = self.private_parent_key_to_private_child_key(parent_private_key, parent_chain_code, child_index)
        extended_key = self.extended_key("private main", parent_depth + 1, child_index, child_private_key, parent_private_key, chain_code)
        return extended_key

    def public_parent_key_to_public_child_key(self, compressed_parent_public_key, chain_code, index):
        """
        check whether i >= 2^31
        if so return failure
        else I=HMAC-SHA512(key=c_par, data=ser_p(K_par) ||ser_32(i))
        split I into 2 32 byte sequences I_L and I_R
        the returned child key K_i is point(parse_256(I_L)) + K_par
        c_i = I_R
        #assume compressed parent public key
        """
        hardened = False
        if index >= pow(2,31):
            hardened = True
        index = hex(index)[2:].zfill(8)
        if hardened:
            raise Error
        data = compressed_parent_public_key + index
        hash_bytes = hmac.new(bytes.fromhex(chain_code), bytes.fromhex(data), hashlib.sha512).digest()
        # hash bytes verified by comparison to other code

        left, right = hash_bytes[:32], hash_bytes[32:]

        x1, y1 = self.public_key_pair(left.hex())

        #_, _, _, _, _, compressed_parent_public_key, _ = self.parse_extended_key(extended_parent_public_key)
        uncompressed_parent_public_key = self.decompress_pubkey(compressed_parent_public_key)
        x2, y2 = self.pubkey_to_pair(uncompressed_parent_public_key)
        x3, y3 = self.ECGroupOp(x1, y1, x2, y2)

        # returns uncompressed key
        child_public_key = "04" + hex(x3)[2:].zfill(64) + hex(y3)[2:].zfill(64)
        return child_public_key


    def private_parent_key_to_public_child_key(self):
        pass


    def child_private_key_and_chain_code(self, parent_private_key, parent_chain_code, index):
        index = self.int_to_8bit_hex(index)
        data = "00" + parent_private_key + index
        hash_bytes = hmac.new(bytes.fromhex(parent_chain_code), bytes.fromhex(data), hashlib.sha512).digest()
        left, right = hash_bytes[:32], hash_bytes[32:]
        child_key, new_chain_code = left.hex(), right.hex()
        return child_key, new_chain_code

    def child_private_key_from_parent_private_key1(self, index, parent_private_key, parent_chain_code):
        index = self.int_to_8bit_hex(index)
        seed = parent_private_key + parent_chain_code + index
        private_child_key, chain_code = self.private_key_and_chain_code(seed) #hmac and split
        return private_child_key, chain_code

    def child_private_key_from_parent_private_key2(self, index, parent_private_key, parent_chain_code):
        index = self.int_to_8bit_hex(index)
        seed = parent_private_key + parent_chain_code + index
        private_child_key, chain_code = self.private_key_and_code(seed) #hmac and split
        order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        private_child_key = int(private_child_key,16) + int(parent_private_key,16) % order
        private_child_key = hex(private_child_key)[2:]
        return private_child_key, chain_code

    def child_public_key_from_parent_public_key(self, index, parent_public_key, parent_chain_code):
        # convert index from int to 32 bits of hex
        index = self.int_to_8bit_hex(index)
        seed = parent_public_key + parent_chain_code + index
        public_child_key, chain_code = self.private_key_and_chain_code(seed)
        public_child_key = public_child_key + parent_public_key
        return public_child_key, chain_code


    # * * * address generation * * *

    def generate_address_from_public_key(self, public_key):
        """
        keccak256 hash the public, then take last 20 bytes to get the ethereum address

        :param public_key:
        :return:
        """
        #strip hex "04" prefix from the beginning of public key
        public_key = public_key[2:]
        k = keccak.new(digest_bits=256)
        public_key_string = str(public_key)
        k.update(bytes.fromhex(public_key_string))
        hashed_key = k.hexdigest()
        address = hashed_key[-40:] #last 20 bytes = 40 chars
        return address

    def list_addresses(self):
        #get master public address
        # does it make sense to store the tree shape but not the values?
        #addressess are created in order, with a max number of children for each row
        pass

    def generate_address_from_private_key(self, private_key):
        public_key = self.uncompressed_public_key(private_key)
        address = self.generate_address_from_public_key(public_key)
        return address

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

    # * * * utils * * *
    def parse_extended_key(self, extended_key):
        #base58check
        extended_key = base58.b58decode(extended_key).hex()
        network = extended_key[:8]
        depth = extended_key[8:10]
        fingerprint = extended_key[10:18]
        child_number = extended_key[18:26]
        chain_code = extended_key[26:90]
        key = extended_key[90:156]
        if key[:2] == "00":
            key = key[2:]
        check = extended_key[156:]
        return network, depth, fingerprint, child_number, chain_code, key, check

    def version_bytes(self, network):
        version = {'public main': '0488b21e',
                   'private main': '0488ade4',
                   'public test': '043587cf',
                   'private test': '04358394'}
        return version[network]

    def network_from_bytes(self, version_bytes):
        network = {"0488b21e": "public main",
                   "0488ade4": "private main",
                   "043587cf": "public test",
                   "04358394": "private test"}
        return network[version_bytes]

    def neuter_key(self, extended_private_key):
        private_network, depth, fingerprint, child_number, chain_code, key, check = self.parse_extended_key(extended_private_key)
        network = self.network_from_bytes(private_network)
        network = "public " + network.split()[1]
        public_network = self.version_bytes(network)
        if int(child_number, 16) >= pow(2,31):
            raise Error
        key = self.compressed_public_key(key)
        extended = public_network + depth + fingerprint + child_number + chain_code + key

        hash1 = hashlib.sha256(bytes.fromhex(extended)).digest()
        hash2 = hashlib.sha256(hash1).hexdigest()
        checksum = hash2[:8]

        encoded_string = base58.b58encode(bytes.fromhex(extended + checksum)).decode('utf-8')
        return encoded_string



def new_wallet(name):
    new_wallet = TurtleWallet(name)
    entropy = new_wallet.generate_entropy(128)
    mnemonic_words = new_wallet.mnemonic_words(entropy)
    print("Write down your mnemonic words (in order) and store them in safe place.")
    print("If you lose them, you may not be able to recover the wallet and associated funds")
    print("mnemonic_words: ", mnemonic_words)
    while True:
        print("type 'yes' to continue")
        continue_ = input()
        if continue_ == "yes":
            break
    seed = new_wallet.mnemonic_to_seed(mnemonic_words)
    private_key, public_key, chain_code = new_wallet.generate_master_keys_and_codes(seed)
    #public_key0 = new_wallet.generate_child_public_key(parent_public_key, chain_code, index=0)
    #private_key0 = new_wallet.generate_child_private_key(parent_private_key, chain_code, index=0)

    wallet_info = {"name": name, "info": {"master_private_key": private_key, "master_public_key": public_key, "children": 1}}
    # serialize
    #save to json file
    with open('data.txt', 'a') as f:
        json.dump(wallet_info, f)
        f.write('\n')

def access_wallet_json(name):
    # search json
    data = []
    with open('data.txt') as f:
        for line in f:
            data.append(json.loads(line))
    #search data
    for json_wallet in data:
        if name == json_wallet['name']:
            return json_wallet
    return None

def access_wallet(name):
    #get wallet from json

    return access_wallet_json(name)
    wallet_dict = access_wallet_json(name)

def build_wallet(wallet_dict):
    #constuct wallet
    wallet = TurtleWallet.build_wallet(wallet_dict)
    return wallet

def list_wallets():
    with open('data.txt') as f:
        [print(x) for x in range(10)]
        wallet_names = [json.loads(line)['name'] for line in f]
        for name in wallet_names:
            print(name)

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
    test_wallet = TurtleWallet("test")
    seed = test_wallet.generate_entropy(128)
    print(seed)
    mnemonic_words = test_wallet.mnemonic_words(seed)
    seed2 = test_wallet.mnemonic_to_seed(mnemonic_words)
    print(seed2)
    #self.assertEqual(seed, seed2)


def test_child_keys():
    a = TurtleWallet("test")
    seed = "000102030405060708090a0b0c0d0e0f"
    #create private key, chain code from seed
    private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
    public_key = a.uncompressed_public_key(private_key)
    # create master private key
    xprv = a.extended_master_private_key(private_key, chain_code, 'private main')
    xpub = a.extended_master_public_key(public_key, chain_code)

    #print('public_key:', public_key)
    child_private_key1, child_chain1 = a.child_private_key_from_parent_private_key(1, private_key, chain_code)
    child_public_key1, child_chain12 = a.child_public_key_from_parent_public_key(1, public_key, chain_code)
    child_public_key12 = a.uncompressed_public_key(child_private_key1)
    print("child private key from private")
    print(child_private_key1)
    print("child public key from private via has")
    print(child_public_key1)
    print("child public key direct from private")
    print(child_public_key12)
    print(child_public_key12 == child_public_key1)
    print(child_chain12 == child_chain1)

    print(a.extended_key("private main", depth=1, index=0, ))

    #self.assertEqual(child_public_key12, child_public_key1)
    #self.assertEqual(child_chain12, child_chain1)


def test_extended_m_0():
    #https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    a = TurtleWallet("test")
    seed = "000102030405060708090a0b0c0d0e0f"
    private_key, chain_code = a.generate_master_private_key_and_chain_code(seed)
    #public_key = a.uncompressed_public_key(private_key)
    expected_ext_priv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    actual_ext_priv = a.extended_master_private_key(private_key, chain_code, 'private main')
    print(expected_ext_priv, actual_ext_priv)
    print(expected_ext_priv == actual_ext_priv)

    child_private_key, chain_code0 = a.child_private_key_from_parent_private_key(0, private_key, chain_code)
    actual_child_ext_private_key = a.extended_key('private main', 1, 0, child_private_key, private_key, chain_code)
    expected_ext_priv_m0 = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    print(actual_child_ext_private_key)
    print(expected_ext_priv_m0)
    print(actual_child_ext_private_key == expected_ext_priv_m0)


    #expected_ext_pub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    #actual_ext_pub = a.extended_master_public_key(public_key, chain_code, 'public main')
    #self.assertEqual(expected_ext_priv, actual_ext_priv)
    #self.assertEqual(expected_ext_pub, actual_ext_pub)

    """
    hex representation of expected_extended_child_private_key m/0:
    164
    0488ade4 01 3442193e 80000000 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141 00 edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea 0a794dec
    version index finger childnumber chaincode                                                     private key                                                        checksum
    
    
    
    """



if __name__ == '__main__':
    test_extended_m_0()
    #test_child_keys()
    pass
    #test_seed_to_mnemonic_and_back()
    #test_master_private_key()