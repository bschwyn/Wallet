import argparse
import main
import sys
from main import TurtleWallet

def new_wallet(name):
    main.new_wallet(name)

def access_wallet(name):
    return main.access_wallet(name)


"python cli.py --wallet"


parser = argparse.ArgumentParser()
parser.add_argument("--wallet", action="store_true")
parser.add_argument("--transact", action="store_true")
args = parser.parse_args()
if args.wallet:
    print("Enter wallet name:")
    name = input()
    wallet = access_wallet(name)
    print("wallet", wallet)
    if not wallet:
        print(f"A wallet with that name does not exist. Do you wish to create one?")
        while True:
            print("type 'yes' or 'no':")
            create_new = input()
            if create_new == 'yes':
                print(f"creating wallet with name {name}")
                new_wallet(name)
                wallet = access_wallet(name)
                break
            elif create_new == 'no':
                sys.exit()

    #now do stuff with wallet?
    #add address
    # do you want to create a new address?
    print("wallet created")
    sys.exit() #until I fix / implement the next part

    #wallet.list_addressses() # lists public addresses
    print("Do you want to create a new address")
    while True:
        print("type 'yes' or 'no':")
        new_address = input()
        if new_address == 'yes':
            # something about this one bugs me.
            addr = wallet.generate_new_child_private_public_address()
if args.list_wallets:
    pass
    # list wallets
if args.transact:
    print("creating transaction")
    print("Enter the name of your wallet:")
    wallet = input()
    print(f"Wallet name is {wallet}")
    print("Enter amount in Eth:")
    value = input()
    print(f"value is {value}")
    print(f"Enter destination address:")
    to_address = input()
    print(f"destination address is {to_address}")

    print("Verify the following information is correct: ")
    print("value: ", value, " destination: ", to_address)
    print("Do you wish to proceed with the transaction? Type 'Yes' to proceed, 'No' to cancel")
    proceed = input()
    if proceed == "Yes":
        pass
        # do transaction
