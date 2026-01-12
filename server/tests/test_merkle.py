## Tests the basic operation of merkle tree data structures

import sys
import os
import json
import glob

# Path setup to import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from merkle import SoftwareRegistry

def run_file_test():
    registry = SoftwareRegistry()
    
    # Define the path to your data folder
    data_folder = os.path.join(os.path.dirname(__file__), 'data')
    
    # Find all .json files in a/tests/data
    json_files = glob.glob(os.path.join(data_folder, "*.json"))
    
    if not json_files:
        print(f"No JSON files found in {data_folder}")
        return

    print(f"Found {len(json_files)} files. Processing...\n")

    # Load and process each file
    for file_path in sorted(json_files): # Sorted to maintain consistent order
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            filename = os.path.basename(file_path)
            print(f"--- Processing: {filename} ---")
            registry.add_entry(data)


if __name__ == "__main__":
    run_file_test()