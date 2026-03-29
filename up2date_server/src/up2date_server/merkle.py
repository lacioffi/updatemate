import json
from pymerkle import InmemoryTree as MerkleTree
from datetime import datetime
from up2date_server.classes import SoftwareVersion, SoftwareReview

class SoftwareRegistry:
    def __init__(self):
        # The Registry: Tracks the birth of each product tree
        self.master_tree = MerkleTree()
        # Storage: Maps product names to their specific Merkle Trees
        self.product_trees = {}
        # User input: For each software version, keeps track of received user comments
        self.version_trees = {}

    def add_software_version(self, software_version: SoftwareVersion): 
        """
        1. Finds/Creates product tree.
        2. Appends full file to product tree.
        3. If it's the first time seeing the product, registers it in Master.
        """
        software_name = software_version.file_properties.StringFileInfo["ProductName"]
        
        #Add first seen date to software/version
        now = datetime.now()
        current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
        software_version.first_seen = current_time_string

        # Consistent serialization for the audit log
        software_version_hash = software_version.signatures[0].hash
        software_version_id = software_name.replace(" ", "_")  + "-" + software_version_hash

        software_data = json.dumps(software_version.__dict__, default=lambda o: o.__dict__, sort_keys=True) # Sort keys for consistent hashing

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

    def add_version_review(self, software_version_id, review: SoftwareReview):
        if software_version_id in self.version_trees:
            #Add received date
            now = datetime.now()
            current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
            review.time_received = current_time_string

            review_data = json.dumps(review.__dict__, default=lambda o: o.__dict__, sort_keys=True) # Sort keys for consistent hashing
            self.version_trees[software_version_id].append_entry(review_data.encode('utf-8'))

        else:
            print(f"{software_version_id} not found in system. You must first upload the version's data before submitting a comment.")

    def get_human_readable_report(self, software_name, print_certs=True):
        """Standard lookup for an auditor"""
        output = ""
        if software_name not in self.product_trees:
            output += f"Product {software_name} not found."
            return

        tree: MerkleTree = self.product_trees[software_name]
        output += f"\n======Human readable report for {software_name}======\n"
        output += f"Total Versions: {tree.get_size()}\n"
        output += f"Latest Root Hash: {tree.root.digest.hex()}\n"

        for leaf in tree.leaves:
            version_data = json.loads(leaf.data)
            software_version = SoftwareVersion(version_data)
            output += f"\n>>> Details for version: {software_version.file_properties.StringFileInfo['ProductVersion']}\n"
            output += f"First seen date: {version_data['first_seen']}\n"
            version_id = software_name.replace(" ", "_") + '-' + version_data["signatures"][0]["hash"]
            output += f"Version ID: {version_id}\n"
            output += f"Signature information:\n"
            output += f"\tSignature hash: {version_data['signatures'][0]['hash']}\n"
            if(print_certs):
                output += f"\tCertificate chain:\n"
                for certificate in version_data["signatures"][0]["certificates"]:
                    output += f"\t\tIssuer: {certificate['issuer']}\n"
                    output += f"\t\tSubject: {certificate['subject']}\n"
                    output += f"\t\tValid From: {certificate['valid_from']}\n"
                    output += f"\t\tValid To: {certificate['valid_to']}\n"
            output += f"\tReviews for version: \n"
            if len(self.version_trees[version_id].leaves) == 0:
                output += f"\t\tNo reviews submitted yet!\n"
            else:
                for review in self.version_trees[version_id].leaves:
                    output += f'\t\t{review.data}\n'

        print(output)
        return output

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
    
    def get_version_reviews(self, version_id):
        """Standard lookup for an auditor"""

        reviews = []
        for review in self.version_trees[version_id].leaves:
            reviews.append(review.data)

        return reviews
