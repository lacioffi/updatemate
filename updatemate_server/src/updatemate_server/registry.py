from updatemate_server.merkle import SoftwareRegistry

DATA_PATH = "merkle_data/"  # Path to store Merkle trees and data files
main_registry = SoftwareRegistry(DATA_PATH)  # Master registry for all software products