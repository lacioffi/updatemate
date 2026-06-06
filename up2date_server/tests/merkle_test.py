## Tests the basic operation of merkle tree data structures

import sys
import os
import json
import time
import glob
import pytest
from up2date_server.merkle import SoftwareRegistry, SoftwareReview
from up2date_server.classes import SoftwareVersion

DATA_PATH = "merkle_test_data/"

# Path setup to import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

### Setup ###
#Ensure merkle data folder exists
if not os.path.exists(DATA_PATH):
    os.makedirs(DATA_PATH)

#Delete existing merkle data
for filename in os.listdir(DATA_PATH):
    file_path = os.path.join(DATA_PATH, filename)
    try:
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.remove(file_path)  # Deletes files or symbolic links
    except Exception as e:
        print(f'Failed to delete {file_path}. Reason: {e}')

#Create and build new registry
main_registry = SoftwareRegistry(DATA_PATH)

# Path to data folder
data_folder = os.path.join(os.path.dirname(__file__), 'data')

# Find all .json files in a/tests/data
json_files = glob.glob(os.path.join(data_folder, "*.json"))

# Load and process each file
for file_path in json_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.loads(f.read())
        software_version = SoftwareVersion(data)
        #filename = os.path.basename(file_path)
        #print(f"--- Processing: {filename} ---")
        main_registry.add_software_version(software_version)


def test_get_software_versions():
    versions = main_registry.get_software_versions("Google Chrome")
    print(versions)
    assert len(versions) == 3
    assert versions[0]["signatures"][0]["hash"] == "676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    assert versions[1]["signatures"][0]["hash"] == "ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f"

def test_human_readable_report():
    report = main_registry.get_human_readable_report("Google Chrome", print_certs=False)
    assert "Version ID: Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f" in report

def test_software_reviews():
    review_data = {
        "reviewer": "Alice",
        "comment": "This version is vulnerable to CVE-something.",
        "review": "vulnerable"
    }
    review = SoftwareReview(review_data)
    main_registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review)
    main_registry.add_version_review("Google_Chrome-82ad9ce8534e6de68cebc14699b28509c8c85fda36100d09ab79919c16c217f7", review)
    reviews = main_registry.get_version_reviews("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429")
    assert len(reviews) == 1
    assert reviews[0]["review"] == "vulnerable"
    
def test_get_software_report():
    report = main_registry.get_human_readable_report("Google Chrome")
    assert "Version ID: Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f" in report
    print(report)
