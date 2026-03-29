## Tests the basic operation of merkle tree data structures

import sys
import os
import json
import time
import glob
import pytest
from up2date_server.merkle import SoftwareRegistry
from up2date_server.classes import SoftwareVersion

# Path setup to import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def test_build_version_tree():
    registry = SoftwareRegistry()

    # Path to data folder
    data_folder = os.path.join(os.path.dirname(__file__), 'data')
    
    # Find all .json files in a/tests/data
    json_files = glob.glob(os.path.join(data_folder, "*.json"))
    
    if not json_files:
        #print(f"No JSON files found in {data_folder}")
        return

    #print(f"Found {len(json_files)} files. Processing...\n")

    # Load and process each file
    for file_path in json_files:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
            software_version = SoftwareVersion(data)
            filename = os.path.basename(file_path)
            #print(f"--- Processing: {filename} ---")
            registry.add_software_version(software_version)

@pytest.fixture
def build_test_tree():
    registry = SoftwareRegistry()

    # Path to data folder
    data_folder = os.path.join(os.path.dirname(__file__), 'data')
    
    # Find all .json files in a/tests/data
    json_files = glob.glob(os.path.join(data_folder, "*.json"))
    
    if not json_files:
        #print(f"No JSON files found in {data_folder}")
        return

    # Load and process each file
    for file_path in json_files:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
            software_version = SoftwareVersion(data)
            filename = os.path.basename(file_path)
            #print(f"--- Processing: {filename} ---")
            registry.add_software_version(software_version)
    
    return registry

def test_get_software_versions(build_test_tree):
    registry = build_test_tree
    versions = registry.get_software_versions("Google Chrome")
    assert len(versions) == 2
    assert versions[0]["signatures"][0]["hash"] == "676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    assert versions[1]["signatures"][0]["hash"] == "ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f"

def test_human_readable_report(build_test_tree):
    registry = build_test_tree
    report = registry.get_human_readable_report("Google Chrome", print_certs=False)
    assert "Version ID: Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f" in report

""" #Heuristics (will be moved to another file in the future)
def check_freeze_attack(registry, software_name, version_id):
    #Get all versions for software
    registry: SoftwareRegistry = registry
    versions = registry.get_software_versions(software_name)

    newest_version_first_seen = ""
    current_version_first_seen = ""
    for version in versions:
        i_version_first_seen = version["first_seen"]
        i_version_id = software_name.replace(" ", "_") + '-' + version["signatures"][0]["hash"]

        if i_version_id == version_id:
            current_version_first_seen = i_version_first_seen

        if i_version_first_seen > newest_version_first_seen:
            newest_version_first_seen = i_version_first_seen

    if newest_version_first_seen != current_version_first_seen:
        print(f"A newer version was seen ({newest_version_first_seen}). Your version was first seen on {current_version_first_seen}.")
    else:
        return False #User is in newest version

    current_version_comments = registry.get_version_reviews(software_name, version_id)

    vulnerability_reported = False
    for comment in current_version_comments:
        comment = json.loads(comment)
        if comment["review"] == "vulnerable":
            vulnerability_reported = True

    if vulnerability_reported:
        print(f"Your current version has at least one reported vulnerability. If you are unable to update to a newer version, you may be under a freeze attack.")
        return True
    else:
        return False


def check_replay_attack(registry, software_name, curr_version_id, new_version_id):
    #Get all versions for software
    registry: SoftwareRegistry = registry
    versions = registry.get_software_versions(software_name)

    new_version_first_seen = ""
    current_version_first_seen = ""
    for version in versions:
        i_version_first_seen = version["first_seen"]
        i_version_id = software_name.replace(" ", "_") + '-' + version["signatures"][0]["hash"]

        if i_version_id == curr_version_id:
            current_version_first_seen = i_version_first_seen

        if i_version_id == new_version_id:
            new_version_first_seen = i_version_first_seen

    if new_version_first_seen < current_version_first_seen:
        print(f"The version you received as an update was first seen earlier ({new_version_first_seen}) than your current version {current_version_first_seen}.")
        print("This may indicate you've received an older version of the software instead of a newer one. You may be under a replay attack.")
        return True
    else:
        return False

def check_widespread_malware(registry, software_name, version_id):
    registry: SoftwareRegistry = registry
    
    #Get comments for version
    count_good = 0
    count_bad = 0
    for review in registry.get_version_reviews(software_name, version_id):
        review = json.loads(review)
        if review["review"] == "OK":
            count_good += 1
        if review["review"] == "malicious" or review["review"] == "vulnerable":
            count_bad += 1
    
    bad_proportion = float(count_bad)/(count_good+count_good)
    if bad_proportion > 0.3: #Could be any other value.
        print(f"This version has a large proportion of negative reviews ({bad_proportion:.2f}). It may be malicious.")
        return True
    return False    

def check_targeted_malware(registry, software_name, version_id):
    registry: SoftwareRegistry = registry
    
    #Get comments for version
    comment_count = len(registry.get_version_reviews(software_name, version_id))
    if comment_count < 2:
        print(f"There are very few comments for this version ({comment_count}). You may have received a targeted, malicious version. Proceed with caution.")
        return True
    return False """


""" 
if __name__ == "__main__":
    review_ok = {"review":"OK","comment":"This version is OK."}
    review_vulnerable = {"review":"vulnerable", "comment":"this version is vulnerable to CVE-something"}
    review_bad = {"review":"malicious", "comment":"this version is malicious! It deleted all my files!"}

    # Basic test
    print("========= BASIC TESTS =========")
    registry = SoftwareRegistry()
    append_versions_test(registry)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_vulnerable)
    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok)
    registry.add_version_review("Docker_Desktop_Launcher-e2bac9549c398111009c3b6825ab953b3a3c39b0fc13f1a9b1b0d1a592f28cb3", review_ok)
    #registry.get_human_readable_report("Google Chrome", print_certs=False)

    # Test Freeze attack - A new version is available, but the user is unaware
    registry = SoftwareRegistry()
    append_versions_test(registry)
    print("\n")

    print("===== Freeze Attack detection test =====")
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_vulnerable)

    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok) #Newest version
    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok)
    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok)
    registry.get_human_readable_report("Google Chrome", print_certs=False)
    check_freeze_attack(registry, "Google Chrome", "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429")
    print("\n")

    # Test Replay Attack - The user is in a newer version, and receives an older version as a replacement
    registry = SoftwareRegistry()
    append_versions_test(registry)
    print("\n")

    print("===== Replay Attack detection test =====")
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok) #Older version
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)

    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok) #Newest version
    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok)
    registry.add_version_review("Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", review_ok)

    registry.get_human_readable_report("Google Chrome", print_certs=False)
    check_replay_attack(registry, "Google Chrome", "Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f", "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429")

    # Test widespread malware - Software with a bunch of negative comments
    registry = SoftwareRegistry()
    append_versions_test(registry)
    print("\n")

    print("===== Widespread malware detection test =====")
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_bad)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_bad)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_bad)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_bad)

    registry.get_human_readable_report("Google Chrome", print_certs=False)
    check_widespread_malware(registry, "Google Chrome", "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429")
    print("\n")

    # Test targeted malware - Update sent to only a few users
    registry = SoftwareRegistry()
    append_versions_test(registry)
    print("\n")

    print("===== Targeted malware detection test =====")
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.add_version_review("Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429", review_ok)
    registry.get_human_readable_report("Google Chrome", print_certs=False)
    check_targeted_malware(registry, "Google Chrome", "Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f")

    print("\n")

     """