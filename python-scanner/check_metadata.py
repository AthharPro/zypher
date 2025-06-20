import os
import json
import sys

# Find the rule_metadata.json file
base_dir = os.path.dirname(os.path.abspath(__file__))
possible_paths = [
    os.path.join(base_dir, "zypher_scanner", "data", "rule_metadata.json"),
    os.path.join(base_dir, "data", "rule_metadata.json"),
    os.path.join(os.path.dirname(base_dir), "data", "rule_metadata.json"),
]

print("Checking for rule_metadata.json file...")
found = False

for path in possible_paths:
    if os.path.exists(path):
        print(f"Found metadata file at: {path}")
        found = True
        try:
            with open(path, 'r') as f:
                metadata = json.load(f)
            print("Successfully loaded JSON:")
            print(f"Number of rules: {len(metadata.get('rules', []))}")
            for rule in metadata.get('rules', []):
                print(f"Rule: {rule.get('id')} - {rule.get('name')} - Severity: {rule.get('severity')}")
        except Exception as e:
            print(f"Error loading JSON: {e}")

if not found:
    print("Could not find rule_metadata.json file!")
    print(f"Current directory: {base_dir}")
    print(f"Files in current directory: {os.listdir(base_dir)}")
    scanner_dir = os.path.join(base_dir, 'zypher_scanner')
    if os.path.exists(scanner_dir):
        print(f"Files in zypher_scanner directory: {os.listdir(scanner_dir)}")
        data_dir = os.path.join(scanner_dir, 'data')
        if os.path.exists(data_dir):
            print(f"Files in data directory: {os.listdir(data_dir)}")
