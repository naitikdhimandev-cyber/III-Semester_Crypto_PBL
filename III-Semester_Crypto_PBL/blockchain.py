import hashlib
import json
import time
from datetime import datetime
import os

class Block:
    def __init__(self, index, data, previous_hash, timestamp=None):
        self.index = index
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, data):

        block = cls(
            index=data['index'],
            data=data['data'],
            previous_hash=data['previous_hash'],
            timestamp=data['timestamp']
        )

        if block.hash != data['hash']:
            raise ValueError("Block hash does not match data!")
        return block



class Blockchain:
    def __init__(self, storage_file='blockchain.json'):
        self.storage_file = storage_file
        self.chain = []
        self.load_chain()

        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_data = {
            'sender_id': 0,
            'receiver_id': 0,
            'cipher_text': "Genesis Block",
            'key_text': ""
        }
        genesis_block = Block(0, genesis_data, "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def get_last_block(self):
        return self.chain[-1] if self.chain else None

    def add_block(self, sender_id, receiver_id, cipher_text, key_text):

        last_block = self.get_last_block()
        
        block_data = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'cipher_text': cipher_text,
            'key_text': key_text
        }
        
        new_block = Block(
            index=len(self.chain),
            data=block_data,
            previous_hash=last_block.hash if last_block else "0"
        )
        
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def save_chain(self):
        """Save the blockchain to a JSON file."""
        with open(self.storage_file, 'w') as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)

    def load_chain(self):
        """Load the blockchain from a JSON file."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    chain_data = json.load(f)
                    self.chain = [Block.from_dict(block) for block in chain_data]
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Error loading blockchain: {e}")
                self.chain = []

    def is_chain_valid(self):
        """
        Verify the integrity of the blockchain.
        
        Returns:
            tuple: (is_valid: bool, invalid_blocks: list[int])
        """
        invalid_blocks = []
        
        # Check genesis block
        if len(self.chain) > 0:
            genesis = self.chain[0]
            if (genesis.index != 0 or 
                genesis.previous_hash != '0' or 
                genesis.hash != genesis.calculate_hash()):
                invalid_blocks.append(0)
        
        # Check all blocks
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            is_valid = True
            
            # Check block structure
            if not all(hasattr(current_block, attr) for attr in 
                      ['index', 'timestamp', 'data', 'previous_hash', 'hash']):
                is_valid = False
            
            elif current_block.hash != current_block.calculate_hash():
                is_valid = False
                
            elif current_block.previous_hash != previous_block.hash:
                is_valid = False
                
            elif current_block.index != i:
                is_valid = False
                
            elif not isinstance(current_block.data, dict) or \
                 not all(key in current_block.data for key in 
                        ['sender_id', 'receiver_id', 'cipher_text', 'key_text']):
                is_valid = False
                
            try:
                block_time = datetime.strptime(current_block.timestamp, "%Y-%m-%d %H:%M:%S")
                if block_time > datetime.now():
                    is_valid = False
            except (ValueError, TypeError):
                is_valid = False
                
            if not is_valid:
                invalid_blocks.append(i)
        
        return len(invalid_blocks) == 0, invalid_blocks

    def print_chain(self):
        """Print the entire blockchain."""
        for block in self.chain:
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Sender: {block.data['sender_id']}")
            print(f"Receiver: {block.data['receiver_id']}")
            print(f"Cipher: {block.data['cipher_text'][:50]}...")
            print(f"Key: {block.data['key_text'][:20]}...")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print("-" * 50)



blockchain = Blockchain()

if __name__ == "__main__":

    

    blockchain.print_chain()
    

    print(f"Is chain valid? {blockchain.is_chain_valid()}")
