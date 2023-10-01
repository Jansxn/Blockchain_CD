import datetime
from hashlib import sha256
from dilithium.dilithium import Dilithium2
import base64
from double_encryption import verify_message, sign_message

class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = None
        
    def calculate_hash(self):
        return sha256((str(self.sender) + str(self.recipient) + str(self.amount)).encode()).hexdigest()
    
    def sign_transaction(self, private_key, public_key):
        if self.sender != public_key:
            return False
        # print (self.calculate_hash().encode())
        self.signature = sign_message(self.calculate_hash(), private_key)
        return True 
    
    def is_valid(self): #NEEDS TO BE MODIFIED
        if self.sender == None:
            return True
        if self.signature == None or len(self.signature) == 0:
            return False
        public_key = self.sender
        # return public_key.verify(self.calculate_hash().encode(), self.signature)
        return verify_message(self.calculate_hash(), self.signature, public_key)
    
    
    def __str__(self):
        return str(self.sender) + str(self.recipient) + str(self.amount)

class Block:
    def __init__(self,transactions, timestamp, previous_hash, nonce=0):
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return sha256((str(self.transactions) + str(self.timestamp) + str(self.previous_hash) + str(self.nonce)).encode()).hexdigest()
    
    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0"*difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print("Block mined: " + self.hash)
        
    def has_valid_transactions(self):
        for transaction in self.transactions:
            if not transaction.is_valid():
                return False
        return True

    def __str__(self):
        return str(self.transactions) + str(self.timestamp) + str(self.previous_hash) + str(self.hash) + str(self.nonce)
    
class BlockChain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2
        self.pending_transactions = []
        self.mining_reward = 100

    def create_genesis_block(self):
        #Initialized the blockchain with a genesis block
        return Block([], datetime.datetime.now(), "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        
    def mine_pending_transactions(self, mining_reward_address):
        #Gives the mining reward to the user that mines all the pending transacting in the blockchain and creates a new block
        block = Block(self.pending_transactions, datetime.datetime.now(), self.get_latest_block().hash)
        block.mine_block(self.difficulty)
        print("Block successfully mined")
        self.chain.append(block)
        self.pending_transactions = [Transaction(None, mining_reward_address, self.mining_reward)]

    def add_transaction(self, transaction):
        #Adds a new transaction to the list of pending transactions
        if not transaction.sender or not transaction.recipient:
            raise Exception("Transaction must include sender and recipient")
        if not transaction.is_valid():
            raise Exception("Cannot add invalid transaction to chain")
        self.pending_transactions.append(transaction)
        
    def get_balance_of_address(self, address):
        #Gives the balance of the user with the given address
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address:
                    balance -= transaction.amount
                if transaction.recipient == address:
                    balance += transaction.amount
        return balance
    
    def is_chain_valid(self):
        #Checks if the blockchain has been tampered with
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            if not current_block.has_valid_transactions():
                return False
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
            
        return True

    def __str__(self):
        return str(self.chain)