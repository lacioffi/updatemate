import json
from pymerkle import InmemoryTree as MerkleTree
from datetime import datetime

class SoftwareRegistry:
    def __init__(self):
        # The Registry: Tracks the birth of each product tree
        self.master_tree = MerkleTree()
        # Storage: Maps product names to their specific Merkle Trees
        self.product_trees = {}
        # User input: For each software version, keeps track of received user comments
        self.version_trees = {}

    def add_software_version(self, sw_json_data): 
        """
        1. Finds/Creates product tree.
        2. Appends full file to product tree.
        3. If it's the first time seeing the product, registers it in Master.
        OBS: Receives the entire JSON as input
        """
        props = sw_json_data.get("file_properties", {}).get("StringFileInfo", {})
        software_name = props.get("ProductName", "Unknown")
        print(software_name)
        
        #Add first seen date to software/version
        now = datetime.now()
        current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
        sw_json_data["first_seen"] = current_time_string

        # Consistent serialization for the audit log
        software_data = json.dumps(sw_json_data, sort_keys=True)
        
        software_version_hash = sw_json_data["signatures"][0]["hash"]
        software_version_id = software_name.replace(" ", "_")  + "-" + software_version_hash

        if software_name not in self.product_trees:
            # Create the product-specific tree    
            self.product_trees[software_name] = MerkleTree()
            self.product_trees[software_name].append_entry(software_data.encode('utf-8')) # Add the first version. 
            
            # REGISTER the new tree in the Master Tree, using the software's name
            self.master_tree.append_entry(b'{name}') 
            print(f"[REGISTERED] {software_name} added to Master Tree.")

            #Create reviews tree for first version
            self.version_trees[software_version_id] = MerkleTree()
        else:
            # Existing software: Only adds the version to the log and create the reviews tree for that version, IF the version has not been seen before
            if software_version_id not in self.version_trees:
                self.product_trees[software_name].append_entry(software_data.encode('utf-8'))
                print(f"[UPDATED] {software_name} tree now has {self.product_trees[software_name].get_size()} entries.")
                self.version_trees[software_version_id] = MerkleTree()

    def add_version_review(self, software_version_id, review):
        if software_version_id in self.version_trees:
            #Add received date
            now = datetime.now()
            current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
            review["time_received"] = current_time_string

            review_data = json.dumps(review, sort_keys=True)

            self.version_trees[software_version_id].append_entry(review_data.encode('utf-8'))

        else:
            print(f"{software_version_id} not found in system. You must first upload the version's data before submitting a comment.")

    def get_human_readable_report(self, software_name, print_certs=True):
        """Standard lookup for an auditor"""
        if software_name not in self.product_trees:
            print(f"Product {software_name} not found.")
            return

        tree: MerkleTree = self.product_trees[software_name]
        print(f"\n======Human readable report for {software_name}======")
        print(f"Total Versions: {tree.get_size()}")
        print(f"Latest Root Hash: {tree.root.digest.hex()}")

        for leaf in tree.leaves:
            version_data = json.loads(leaf.data)
            print(f"\n>>> Details for version: {version_data['file_properties']['StringFileInfo']['ProductVersion']}")
            print(f"First seen date: {version_data["first_seen"]}")
            version_id = software_name.replace(" ", "_") + '-' + version_data["signatures"][0]["hash"]
            print(f"Version ID: {version_id}")
            print(f"Signature information:")
            print(f"\tSignature hash: {version_data["signatures"][0]["hash"]}")
            if(print_certs):
                print(f"\tCertificate chain:")
                for certificate in version_data["signatures"][0]["certificates"]:
                    print(f"\t\tIssuer: {certificate["issuer"]}")
                    print(f"\t\tSubject: {certificate["subject"]}")
                    print(f"\t\tValid From: {certificate["valid_from"]}")
                    print(f"\t\tValid To: {certificate["valid_to"]}")
            print(f"\tReviews for version: ")
            if len(self.version_trees[version_id].leaves) == 0:
                print("\t\tNo reviews submitted yet!")
            else:
                for review in self.version_trees[version_id].leaves:
                    print(f'\t\t{review.data}')

    def get_software_versions(self, software_name):
        """Standard lookup for an auditor"""
        if software_name not in self.product_trees:
            print(f"Product {software_name} not found.")
            return

        tree: MerkleTree = self.product_trees[software_name]

        version_data = []
        for leaf in tree.leaves:
            version_data.append(json.loads(leaf.data))
        
        return version_data
    
    def get_version_reviews(self, software_name, version_id):
        """Standard lookup for an auditor"""
        if software_name not in self.product_trees:
            print(f"Product {software_name} not found.")
            return

        reviews = []
        for review in self.version_trees[version_id].leaves:
            reviews.append(review.data)

        return reviews
