import hashlib
import json
import time
from typing import List, Dict, Any

# ========== БЛОКЧЕЙН КЛАССЫ ==========
class Block:
    """Класс блока в блокчейне"""
    def __init__(self, index: int, transactions: List[Dict], previous_hash: str, difficulty: int = 2):
        self.index = index
        self.timestamp = int(time.time())
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.difficulty = difficulty
        self.merkle_root = self._calculate_merkle_root()
        self.hash = self._calculate_hash()

    def _calculate_merkle_root(self) -> str:
        if not self.transactions:
            return ""
        tx_hashes = []
        for tx in self.transactions:
            if isinstance(tx, str):
                tx_string = tx
            else:
                tx_string = json.dumps(tx, sort_keys=True)
            tx_hashes.append(hashlib.sha256(tx_string.encode()).hexdigest())

        while len(tx_hashes) > 1:
            new_hashes = []
            for i in range(0, len(tx_hashes), 2):
                left = tx_hashes[i]
                right = tx_hashes[i + 1] if i + 1 < len(tx_hashes) else tx_hashes[i]
                combined = left + right
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            tx_hashes = new_hashes
        return tx_hashes[0] if tx_hashes else ""

    def _calculate_hash(self) -> str:
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "difficulty": self.difficulty
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self) -> str:
        target = '0' * self.difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self._calculate_hash()
        return self.hash

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root
        }

class Blockchain:
    """Класс блокчейна"""
    def __init__(self, difficulty: int = 2):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.difficulty = difficulty
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_block = Block(0, [{"type": "GENESIS", "details": "Initial Block"}], "0", self.difficulty)
        genesis_block.mine_block()
        self.chain.append(genesis_block)

    def add_transaction(self, transaction: Dict) -> bool:
        # Добавляем метку времени, если нет
        if "timestamp" not in transaction:
            transaction["timestamp"] = int(time.time())
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self) -> bool:
        if not self.pending_transactions:
            return False
        
        new_block = Block(
            len(self.chain),
            self.pending_transactions.copy(),
            self.chain[-1].hash,
            self.difficulty
        )
        new_block.mine_block()
        self.chain.append(new_block)
        self.pending_transactions = []
        return True

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            if current.hash != current._calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def get_chain_data(self) -> List[Dict]:
        return [block.to_dict() for block in self.chain]
