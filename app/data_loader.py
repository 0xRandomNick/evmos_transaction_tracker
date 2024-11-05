# app/data_loader.py

import os
import pandas as pd
import json
import csv
from eth_utils import to_checksum_address

# Get the directory where this script is located
current_dir = os.path.dirname(os.path.abspath(__file__))

def load_method_signatures():
    signature_file = os.path.join(current_dir, 'method_signatures.xlsx')
    try:
        signature_df = pd.read_excel(signature_file)
        # Strip '0x' from signatures
        signature_df['Signature'] = signature_df['Signature'].apply(lambda x: x[2:] if isinstance(x, str) and x.startswith('0x') else x)
        signature_library = dict(zip(signature_df['Signature'], signature_df['Method']))
        return signature_library
    except FileNotFoundError:
        print(f"Error: Method signatures file '{signature_file}' not found.")
        return {}
    except Exception as e:
        print(f"Error loading method signatures: {e}")
        return {}

def load_address_name_map():
    file_path = os.path.join(current_dir, 'address_name_map.json')
    try:
        with open(file_path, 'r') as file:
            address_name_map = json.load(file)
        return address_name_map
    except FileNotFoundError:
        print(f"Error: Address name map file '{file_path}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Address name map file '{file_path}' contains invalid JSON.")
        return {}
    except Exception as e:
        print(f"Error loading address name map: {e}")
        return {}

def load_contract_library():
    file_path = os.path.join(current_dir, 'contract_library.json')
    try:
        with open(file_path, 'r') as file:
            contract_library_data = json.load(file)
            contract_library = {
                to_checksum_address(item['Contract Address']): item for item in contract_library_data
            }
        return contract_library
    except FileNotFoundError:
        print(f"Error: Contract library file '{file_path}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Contract library file '{file_path}' contains invalid JSON.")
        return {}
    except Exception as e:
        print(f"Error loading contract library: {e}")
        return {}

def load_ibc_denom_library():
    ibc_denom_library = {}
    filename = 'ibc_denom library.csv'
    file_path = os.path.join(current_dir, filename)
    try:
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                ibc_denom = row['Denom'].strip()
                symbol = row['Symbol'].strip()
                exponent_str = row['Exponent'].strip()
                try:
                    exponent = int(exponent_str)
                except ValueError:
                    print(f"Warning: Invalid exponent '{exponent_str}' for denom '{ibc_denom}'. Defaulting to 6.")
                    exponent = 6  # Default exponent
                ibc_denom_library[ibc_denom] = {
                    'Symbol': symbol,
                    'Exponent': exponent
                }
    except FileNotFoundError:
        print(f"Error: IBC denom library file '{file_path}' not found.")
    except Exception as e:
        print(f"Error loading IBC denom library: {e}")
    return ibc_denom_library

def load_validator_name_mapping(file_path='Validator_name_mapping.csv'):
    validator_map = {}
    full_file_path = os.path.join(current_dir, file_path)
    try:
        with open(full_file_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                operator_address = row['operatorAddress'].strip().lower()
                name = row['name'].strip()
                validator_map[operator_address] = name
    except FileNotFoundError:
        print(f"Error: Validator mapping file '{full_file_path}' not found.")
    except Exception as e:
        print(f"Error loading validator name mapping: {e}")
    return validator_map
