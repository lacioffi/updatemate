import json
from pathlib import Path
from client.file_manager import analyze_pe


def test_analyze_pe():
    # Path to the binary file
    binary_path = Path(__file__).parent / "data" / "chrome.exe"
    
    # Path to the expected output JSON
    expected_path = Path(__file__).parent / "data" / "output.json"
    
    # Load the expected output
    with open(expected_path, "r") as f:
        expected = json.load(f)
    
    # Analyze the PE file
    result = analyze_pe(str(binary_path))
    
    # Assert that the result matches the expected output
    assert result == expected