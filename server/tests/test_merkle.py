## Tests the basic operation of merkle tree data structures

import sys
import os
import json
import glob

# Path setup to import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from merkle import SoftwareRegistry

def append_versions_test(registry):    
    # Path to data folder
    data_folder = os.path.join(os.path.dirname(__file__), 'data')
    
    # Find all .json files in a/tests/data
    json_files = glob.glob(os.path.join(data_folder, "*.json"))
    
    if not json_files:
        print(f"No JSON files found in {data_folder}")
        return

    print(f"Found {len(json_files)} files. Processing...\n")

    # Load and process each file
    for file_path in json_files:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            filename = os.path.basename(file_path)
            print(f"--- Processing: {filename} ---")
            registry.add_software_version(data)

    #Check if chrome (for example) is loaded correctly:
    print('\n\n')
    registry.get_software_data('Google Chrome')

if __name__ == "__main__":
    registry = SoftwareRegistry()
    append_versions_test(registry)

    #Add a review:
    review = {"comment":"this version is malicious! It deleted all my files!"}
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review)

    registry.get_software_data('Google Chrome')
    #### TO-DO: Test for adding comments.
    #### TO-DO: Test for exploring the tree's state.