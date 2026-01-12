import json
from pymerkle import InmemoryTree as MerkleTree

class SoftwareRegistry:
    def __init__(self):
        # The Registry: Tracks the birth of each product tree
        self.master_tree = MerkleTree()
        # Storage: Maps product names to their specific Merkle Trees
        self.product_trees = {}

    def add_entry(self, file_json):
        """
        1. Finds/Creates product tree.
        2. Appends full file to product tree.
        3. If it's the first time seeing the product, registers it in Master.
        """
        props = file_json.get("file_properties", {}).get("StringFileInfo", {})
        name = props.get("ProductName", "Unknown")
        print(name)
        
        # Consistent serialization for the audit log
        raw_data = json.dumps(file_json, sort_keys=True).encode('utf-8')

        if name not in self.product_trees:
            # Create the product-specific tree    
            self.product_trees[name] = MerkleTree()
            self.product_trees[name].append_entry(raw_data) # Add the first version
            
            # REGISTER the new tree in the Master Tree, using the software's name
            self.master_tree.append_entry(b'{name}')
            print(f"[REGISTERED] {name} added to Master Tree.")
        else:
            # Existing software: Only update the specific tree
            self.product_trees[name].append_entry(raw_data)
            print(f"[UPDATED] {name} tree now has {self.product_trees[name].get_size()} entries.")

    def audit_product(self, name):
        """Standard lookup for an auditor"""
        if name not in self.product_trees:
            print(f"Product {name} not found.")
            return

        tree = self.product_trees[name]
        print(f"\nAudit Report for {name}:")
        print(f"Total Versions: {tree.get_size()}")
        print(f"Latest Root Hash: {tree.root.value}")