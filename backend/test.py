from blockchain import BlockChain, Block, Transaction
import datetime
from dilithium.dilithium import Dilithium2
import base64
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
from double_encryption import verify_message, sign_message, generate_keypair

def BlockChainValidityTest():
    b = BlockChain()
    
    print("Mining blocks")
    b.add_block(Block("transaction", datetime.datetime.now(), "", 0))
    b.add_block(Block("transaction", datetime.datetime.now(), "", 0))
    b.add_block(Block("transaction", datetime.datetime.now(), "", 0))
    
    print(b.is_chain_valid())
    
    b.chain[1].transactions = "hacked"
    b.chain[1].mine_block(b.difficulty)
    print(b.is_chain_valid())
    
def BlockChainMineRewardTest():
    b = BlockChain()
    
    b.add_transaction(Transaction('a', 'b', 100))
    b.add_transaction(Transaction('b', 'a', 50))
    
    print("Mining block")
    b.mine_pending_transactions('x')
    print("Balance of x: ", b.get_balance_of_address('x'))
    
    print("Mining block")
    b.mine_pending_transactions('x')
    print("Balance of x: ", b.get_balance_of_address('x'))
    
def Double_Encryption():
    pk, sk = generate_keypair()
    
    message = "Hello World"
    signature = sign_message(message, sk)
    print(verify_message(message, signature, pk))
    
    message = "Hello World!"
    print(verify_message(message, signature, pk))

def final_test():
    pk, sk = generate_keypair()
    b = BlockChain()
    
    tx1 = Transaction(pk, 'b', 100)
    tx1.sign_transaction(sk, pk)
    b.add_transaction(tx1)
    
    print ("Mining block")
    b.mine_pending_transactions(pk)
    print ("Balance of x: ", b.get_balance_of_address(pk))
    print ("Is chain valid: ", b.is_chain_valid())
    b.chain[1].transactions[0].amount = 1
    print ("Is chain valid: ", b.is_chain_valid())
    
    
    
# BlockChainValidityTest()
# BlockChainMineRewardTest()
# Double_Encryption()
final_test()