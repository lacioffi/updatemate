import json
import os
from pymerkle import SqliteTree
from datetime import datetime
from up2date_server.classes import SoftwareVersion, SoftwareReview

class SoftwareRegistry:
    def __init__(self, path: str):
        # Create data folder if it doesn't exist yet
        if not os.path.exists(path):
            os.makedirs(path)

        # Initialize / connect to main tree
        self.master_tree = SqliteTree(path + "master_tree.db")
        self.path = path

    def add_software_version(self, software_version: SoftwareVersion): 
        software_name = software_version.file_properties.StringFileInfo["ProductName"]
        
        #Add first seen date to software/version
        now = datetime.now()
        current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
        software_version.first_seen = current_time_string

        # Consistent serialization for the audit log
        software_version_hash = software_version.signatures[0].hash
        software_version_id = software_name.replace(" ", "_")  + "-" + software_version_hash

        software_data = json.dumps(software_version.__dict__, default=lambda o: o.__dict__, sort_keys=True) # Sort keys for consistent hashing

        if not self.master_tree.get_entry(software_name.encode('utf-8')): # Check if software is already registered in Master Tree
            # REGISTER the new tree in the Master Tree, using the software's name
            self.master_tree.append_entry(software_name.encode('utf-8')) 
            #print(f"[REGISTERED] {software_name} added to Master Tree.")
        

        with SqliteTree(self.path + f"{software_name}_tree.db") as software_tree:
            software_tree.append_entry(software_data.encode('utf-8')) # Create tree for software if needed. Add version

        if not  os.path.isfile(self.path + f"{software_version_id}_reviews_tree.db"):
            with SqliteTree(self.path + f"{software_version_id}_reviews_tree.db") as reviews_tree:
                pass # Just create the tree for this version's reviews

    def add_version_review(self, software_version_id, review: SoftwareReview):

        if os.path.isfile(self.path + f"{software_version_id}_reviews_tree.db"):
            with SqliteTree(self.path + f"{software_version_id}_reviews_tree.db") as software_tree:
                #Add received date
                now = datetime.now()
                current_time_string = now.strftime("%Y-%m-%d %H:%M:%S")
                review.time_received = current_time_string

                review_data = json.dumps(review.__dict__, default=lambda o: o.__dict__, sort_keys=True) # Sort keys for consistent hashing
                software_tree.append_entry(review_data.encode('utf-8'))

            return("OK")
        else:
            return f"{software_version_id} not found in system. You must first upload the version's data before submitting a comment."

    def get_human_readable_report(self, software_name, print_certs=True):
        """Standard lookup for an auditor"""
        output = ""

        if not os.path.isfile(self.path + f"{software_name}_tree.db"):
            output += f"Product {software_name} not found."
            return output

        with SqliteTree(self.path + f"{software_name}_tree.db") as software_tree:
            tree_size = software_tree.get_size()
            output += f"\n======Human readable report for {software_name}======\n"
            output += f"Total Versions: {tree_size}\n"
            output += f"Latest Root Hash: {software_tree.get_state().hex()}\n"

            for i in range(1, tree_size+1):
                version_data = json.loads(software_tree.get_entry(i).decode('utf-8'))
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

                #Get review data:
                output += f"\tReviews for version: \n"

                if not os.path.isfile(self.path + f"{version_id}_reviews_tree.db"):
                    output += f"\t\tNo reviews submitted yet!\n"
                else:
                    with SqliteTree(self.path + f"{version_id}_reviews_tree.db") as reviews_tree:
                        for i in range(0, reviews_tree.get_size()+1):
                            review = reviews_tree.get_entry(i)
                            output += f'\t\t{review}\n'

        #print(output)
        return output

    def get_software_versions(self, software_name):
        """Standard lookup for an auditor"""
        if not os.path.isfile(self.path + f"{software_name}_tree.db"):
            return f"Product {software_name} not found."

        with SqliteTree(self.path + f"{software_name}_tree.db") as software_tree:
            version_data = []
            for i in range(1, software_tree.get_size()+1):
                leaf = software_tree.get_entry(i)
                version_data.append(json.loads(leaf))
        
        print(version_data)
        return version_data
    
    def get_version_reviews(self, software_version_id):
        """Standard lookup for an auditor"""

        reviews = []

        if os.path.isfile(self.path + f"{software_version_id}_reviews_tree.db"):
            with SqliteTree(self.path + f"{software_version_id}_reviews_tree.db") as software_tree:
                for i in range(1, software_tree.get_size()+1):
                    leaf = software_tree.get_entry(i)
                    reviews.append(json.loads(leaf))
        else:
            return f"{software_version_id} not found in system. You must first upload the version's data before submitting a comment."

        return reviews
