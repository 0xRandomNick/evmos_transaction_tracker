# app/main.py

import datetime
from tqdm import tqdm
from .data_loader import (
    load_method_signatures,
    load_address_name_map,
    load_contract_library,
    load_ibc_denom_library,
    load_validator_name_mapping
)
from .utils import (
    bech32_to_hex,
    hex_to_bech32,
    sanitize,
    rename_address
)
from .evm_processor import decode_evm_transfer_events
from .cosmos_processor import process_cosmos_transactions
from .cointracking_mapper import map_to_cointracking
import requests
import pandas as pd
import base64
import json
import re  # Import regex for address validation

FEE_COLLECTOR_MODULE = 'evmos17xpfvakm2amg962yls6f84z3kell8c5ljcjw34'

def is_bech32_address(address):
    return address.startswith('evmos')  # Adjust the prefix if necessary

def is_hex_address(address):
    pattern = re.compile(r'^(0x)?[0-9a-fA-F]{40}$')
    return bool(pattern.match(address))

def extract_method_name(tx_response, method_sig_to_name):
    # Check if it's an EVM transaction by looking for 'ethereum_tx_hash'
    eth_tx_hash = tx_response.get('ethereum_tx_hash')
    if eth_tx_hash:
        # Extract method signature from the transaction data
        tx = tx_response.get('tx', {})
        body = tx.get('body', {})
        messages = body.get('messages', [])
        if messages:
            message = messages[0]
            msg_data = message.get('data', {})
            data_field = msg_data.get('data')
            if data_field:
                try:
                    # Try base64 decoding first
                    data_bytes = base64.b64decode(data_field)
                except Exception:
                    # If base64 decoding fails, assume hex encoding
                    data_bytes = bytes.fromhex(data_field[2:] if data_field.startswith('0x') else data_field)
                if data_bytes and len(data_bytes) >= 4:
                    method_signature = data_bytes[:4].hex()
                    return method_sig_to_name.get(method_signature, 'Unknown Method')
        return 'Unknown Method'
    else:
        # For Cosmos transactions, default to 'Transaction Fee'
        return 'Transaction Fee'

def fetch_transactions(address, max_transactions=None, api_base_url=None):
    if not api_base_url:
        api_base_url = 'http://88.198.48.87:1317'
    
    # Ensure api_base_url does not end with a slash
    api_base_url = api_base_url.rstrip('/')
    
    # Append the required path to form the complete API URL
    api_url = f"{api_base_url}/cosmos/tx/v1beta1/txs"
    
    transactions = []
    per_page = 100  # Number of transactions per API call

    # Fetch transactions where the address is the sender
    sender_transactions = fetch_transactions_for_event(
        f"message.sender='{address}'",
        api_url,
        per_page,
        max_transactions,
        address  # Pass the address to correctly track it in fee extraction
    )
    transactions.extend(sender_transactions)

    # Fetch transactions where the address is the recipient
    recipient_transactions = fetch_transactions_for_event(
        f"transfer.recipient='{address}'",
        api_url,
        per_page,
        max_transactions,
        address  # Pass the address to correctly track it in fee extraction
    )
    transactions.extend(recipient_transactions)

    # Combine and deduplicate transactions based on 'txhash'
    unique_transactions = {tx['txhash']: tx for tx in transactions}
    transactions = list(unique_transactions.values())

    return transactions


def fetch_transactions_for_event(query, api_url, per_page, max_transactions=None, queried_address=None):
    transactions = []
    current_page = 1

    while True:
        print(f"Fetching transactions for query: {query}, page: {current_page}")

        params = {
            'query': query,
            'order_by': 'ORDER_BY_DESC',  # Ensure descending order
            'limit': str(per_page),
            'page': str(current_page)
        }

        response = requests.get(api_url, params=params)
        if response.status_code != 200:
            print(f"Failed to fetch transactions: {response.text}")
            break

        data = response.json()

        txs = data.get('txs', [])
        tx_responses = data.get('tx_responses', [])

        if not txs:
            break

        for tx_response in tx_responses:
            # Add fee information to each transaction response
            fee_amount, fee_currency = extract_fee(tx_response, queried_address)
            tx_response['fee_amount'] = fee_amount
            tx_response['fee_currency'] = fee_currency

            # Extract Ethereum tx hash if present
            eth_tx_hash = None
            events = tx_response.get('events', [])
            for event_item in events:
                if event_item.get('type') == 'ethereum_tx':
                    attributes = event_item.get('attributes', [])
                    for attr in attributes:
                        if attr.get('key') == 'ethereumTxHash':
                            eth_tx_hash = attr.get('value')
                            tx_response['ethereum_tx_hash'] = eth_tx_hash
                            break
                    if eth_tx_hash:
                        break

            transactions.append(tx_response)

            # Check if we've reached the maximum number of transactions
            if max_transactions and len(transactions) >= max_transactions:
                return transactions

        # Increment the page number
        current_page += 1

        # If max_transactions is set and we've reached it, stop fetching
        if max_transactions and len(transactions) >= max_transactions:
            break

    return transactions[:max_transactions] if max_transactions else transactions


def extract_fee(tx_response, queried_address):
    events = tx_response.get('events', [])
    total_fee_out = 0  # Total amount sent from our wallet to fee collector
    total_fee_in = 0   # Total amount received from fee collector to our wallet
    fee_currency = None

    for event in events:
        if event.get('type') == 'transfer':
            attributes = event.get('attributes', [])
            transfers = []
            current_transfer = {}
            for attr in attributes:
                key = attr.get('key')
                value = attr.get('value')

                # Add key-value to current transfer
                current_transfer[key] = value

                # When we have a complete transfer, process it
                if 'sender' in current_transfer and 'recipient' in current_transfer and 'amount' in current_transfer:
                    transfers.append(current_transfer)
                    current_transfer = {}

            # Process each transfer
            for transfer in transfers:
                sender = transfer.get('sender')
                recipient = transfer.get('recipient')
                amount_str = transfer.get('amount')

                amount, denom = parse_amount(amount_str)
                if sender == queried_address and recipient == FEE_COLLECTOR_MODULE:
                    total_fee_out += amount
                    fee_currency = denom
                elif sender == FEE_COLLECTOR_MODULE and recipient == queried_address:
                    total_fee_in += amount
                    fee_currency = denom

    net_fee = total_fee_out - total_fee_in
    if net_fee != 0:
        return net_fee, fee_currency
    else:
        return None, None


def parse_amount(amount_str):
    import re
    match = re.match(r'(?P<amount>\d+)(?P<denom>.+)', amount_str)
    if not match:
        return None, None
    amount_value = int(match.group('amount')) / 1e18  # Convert from wei to EVMOS
    denom = match.group('denom')
    return amount_value, denom

def contains_cosmos_events(tx_response, cosmos_event_types={'delegate', 'redelegate', 'unbond'}):
    events = tx_response.get('events', [])
    for event in events:
        if event.get('type') in cosmos_event_types:
            return True
    return False


def process_transactions(
    transactions,
    tracked_addresses,
    hex_wallet_addresses,
    output_filename,
    method_sig_to_name,
    address_name_map,
    ibc_denom_library,
    contract_library,
    validator_name_map
):
    """
    Process fetched transactions and map them to CoinTracking format.
    """
    processed_transactions = []
    mapped_tx_hashes = set()  # Track which transactions have been mapped

    # Update address_name_map with hex addresses
    for addr in tracked_addresses:
        address_name_map[addr.lower()] = 'My Wallet'
        try:
            hex_addr = bech32_to_hex(addr).lower()
            address_name_map[hex_addr] = 'My Wallet'
            hex_wallet_addresses.append(hex_addr.lower())
        except ValueError as e:
            print(f"Error converting address {addr}: {e}")

    for tx_response in tqdm(transactions, desc='Processing transactions'):
        # Extract fee information from tx_response
        fee_amount = tx_response.get('fee_amount')
        fee_currency = tx_response.get('fee_currency')

        tx_hash = tx_response['txhash']

        # Determine if the transaction contains Cosmos-specific events
        has_cosmos_event = contains_cosmos_events(tx_response)

        # Determine if the transaction is an EVM transaction
        is_evm_tx = False
        eth_tx_hash = None

        if has_cosmos_event:
            is_evm_tx = False
        else:
            # Updated code: Use events directly
            events = tx_response.get('events', [])
            for event in events:
                if event.get('type') == 'ethereum_tx':
                    is_evm_tx = True
                    attributes = event.get('attributes', [])
                    for attr in attributes:
                        if attr.get('key') == 'ethereumTxHash':
                            eth_tx_hash = attr.get('value')
                            tx_response['ethereum_tx_hash'] = eth_tx_hash
                            break
                    if eth_tx_hash:
                        break


        # Extract Ethereum tx hash if present
        if is_evm_tx:
            # Existing logic to extract Ethereum tx hash from logs
            if not eth_tx_hash:
                # Attempt to extract if not already done
                logs = tx_response.get('logs', [])
                for log in logs:
                    events = log.get('events', [])
                    for event_item in events:
                        if event_item.get('type') == 'ethereum_tx':
                            attributes = event_item.get('attributes', [])
                            for attr in attributes:
                                if attr['key'] == 'ethereumTxHash':
                                    eth_tx_hash = attr['value']
                                    tx_response['ethereum_tx_hash'] = eth_tx_hash
                                    break
                            if eth_tx_hash:
                                break
                    if eth_tx_hash:
                        break

        if is_evm_tx:
            processed_events = process_evm_transaction(
                tx_response,
                hex_wallet_addresses,
                method_sig_to_name,
                contract_library,
                address_name_map,
                fee_amount,
                fee_currency,
                ibc_denom_library
            )
        else:
            processed_events = process_cosmos_transaction(
                tx_response,
                tracked_addresses,
                address_name_map,
                ibc_denom_library,
                contract_library,
                fee_amount,
                fee_currency,
                validator_name_map
            )

        if processed_events:
            processed_transactions.extend(processed_events)
            mapped_tx_hashes.add(tx_hash)


    # After processing all transactions, identify and add standalone Fee entries
    for tx_response in transactions:
        tx_hash = tx_response['txhash']
        fee_amount = tx_response.get('fee_amount')
        fee_currency = tx_response.get('fee_currency')

        # Check if transaction has a fee and has not been mapped
        if fee_amount and fee_currency and tx_hash not in mapped_tx_hashes:
            timestamp = tx_response['timestamp']
            eth_tx_hash = tx_response.get('ethereum_tx_hash', '')  # Extract eth_tx_hash if available

            # Extract method_name using the helper function
            method_name = extract_method_name(tx_response, method_sig_to_name)

            # Create standalone Fee entry with dynamic method_name and updated comment
            if method_name and method_name != 'Transaction Fee':
                fee_comment = f'Fee for {method_name}'
            else:
                fee_comment = 'Fee for Cosmos Tx'

            # Create standalone Fee entry with dynamic method_name
            fee_entry = {
                'timestamp': timestamp,
                'from': 'My Wallet',
                'to': 'Fee Collector',
                'amount': '',
                'token_symbol': '',
                'contract_address': '',
                'transaction_hash': tx_hash,
                'direction': 'out',
                'method': method_name,  # Use extracted method_name or default
                'token_type': '',
                'comment': fee_comment,
                'type': 'Fee',
                'fee_amount': fee_amount,       # Fee already represented by this entry
                'fee_currency': fee_currency,
                'ethereum_tx_hash': eth_tx_hash  # Include Ethereum Tx Hash
            }
            print(f"Adding standalone Fee entry for transaction {tx_hash} with method '{method_name}'")
            processed_transactions.append(fee_entry)

    if not processed_transactions:
        print("No valid transactions to process.")
        return processed_transactions  # Return empty list

    return processed_transactions  # Only return the processed transactions

def process_evm_transaction(
    tx_response,
    hex_wallet_addresses,
    method_sig_to_name,
    contract_library,
    address_name_map,
    fee_amount,
    fee_currency,
    ibc_denom_library
):
    import logging
    logger = logging.getLogger(__name__)
    
    processed_events = []
    tx_hash = tx_response['txhash']
    timestamp = tx_response['timestamp']
    method_name = 'Unknown'

    logger.info(f"Processing EVM transaction: {tx_hash}")

    # EVM transaction processing logic
    # Extract method signature, from/to addresses, value, and decode logs

    # Try to extract method signature from transaction data
    eth_tx_hash = tx_response.get('ethereum_tx_hash', None)
    ethereum_tx_failed = False  # Initialize flag for failed Ethereum transaction
    failure_reason = ''

    # Check for Ethereum transaction failure
    logs = tx_response.get('logs', [])
    for log in logs:
        events = log.get('events', [])
        for event in events:
            if event.get('type') == 'ethereum_tx':
                attributes = event.get('attributes', [])
                for attr in attributes:
                    if attr['key'] == 'ethereumTxFailed':
                        ethereum_tx_failed = True
                        failure_reason = attr['value']
                if ethereum_tx_failed:
                    break
        if ethereum_tx_failed:
            break

    if ethereum_tx_failed:
        logger.warning(f"Ethereum transaction {tx_hash} failed: {failure_reason}")
        # Ethereum transaction failed, create a failed transaction event
        event_dict = {
            'timestamp': timestamp,
            'from': 'My Wallet',
            'to': '',
            'amount': 0,
            'token_symbol': '',
            'contract_address': '',
            'transaction_hash': tx_hash,
            'direction': 'failed',
            'method': method_name,
            'token_type': '',
            'comment': failure_reason,
            'type': 'Failed Transaction',
            'fee_amount': fee_amount,       # Ensure fee is included
            'fee_currency': fee_currency,   # Ensure fee is included
            'ethereum_tx_hash': eth_tx_hash if eth_tx_hash else ''  # Ensure Ethereum Tx Hash is set
        }
        processed_events.append(event_dict)
        return processed_events  # Skip further processing of this transaction

    # Proceed to process successful EVM transaction

    # Extract 'from' and 'to' addresses and 'value'
    from_address_hex = None
    to_address_hex = None
    value = 0

    # Extract 'from' address from 'message' event attributes
    events = tx_response.get('events', [])
    from_address_hex = None
    to_address_hex = None
    value = 0

    for event in events:
        if event.get('type') == 'message':
            attributes = event.get('attributes', [])
            for attr in attributes:
                if attr.get('key') == 'sender':
                    from_address_bech32 = attr.get('value')
                    try:
                        from_address_hex = bech32_to_hex(from_address_bech32).lower()
                        logger.debug(f"From Address (Bech32): {from_address_bech32} -> Hex: {from_address_hex}")
                    except ValueError:
                        from_address_hex = None
                        logger.error(f"Invalid Bech32 address: {from_address_bech32}")
                    break
            if from_address_hex:
                break


    # Extract 'to' address and 'value' from transaction data
    try:
        tx = tx_response.get('tx', {})
        body = tx.get('body', {})
        messages = body.get('messages', [])
        if messages:
            message = messages[0]
            msg_data = message.get('data', {})
            # For EVM transactions, the method signature is in 'data'
            data_field = msg_data.get('data')
            if data_field:
                try:
                    # Try base64 decoding first
                    data_bytes = base64.b64decode(data_field)
                    logger.debug(f"Data field decoded from base64: {data_bytes.hex()}")
                except Exception:
                    # If base64 decoding fails, assume hex encoding
                    data_bytes = bytes.fromhex(data_field[2:] if data_field.startswith('0x') else data_field)
                    logger.debug(f"Data field decoded from hex: {data_bytes.hex()}")
                if data_bytes and len(data_bytes) >= 4:
                    method_signature = data_bytes[:4].hex()
                    method_name = method_sig_to_name.get(method_signature, 'Unknown Method')
                    logger.info(f"Extracted Method Signature: {method_signature} -> Method Name: {method_name}")
            else:
                value_str = msg_data.get('value', '0')
                if int(value_str) > 0:
                    method_name = 'EVM Transfer'
                    logger.info(f"Method Name set to 'EVM Transfer' based on value: {value_str}")
            to_address_hex = msg_data.get('to', '').lower()
            value_str = msg_data.get('value', '0')
            value = int(value_str)
            logger.debug(f"To Address Hex: {to_address_hex}, Value: {value}")
    except Exception as e:
        logger.error(f"Error extracting 'to' and 'value' from transaction {tx_hash}: {e}")

    # Now, check if 'value' > 0
    if value > 0:
        # Convert 'value' from wei to EVMOS
        amount = value / 1e18
        involved = False
        direction = None
        if from_address_hex in hex_wallet_addresses:
            involved = True
            direction = 'out'
            logger.debug(f"Transaction {tx_hash} is outgoing.")
        if to_address_hex in hex_wallet_addresses:
            involved = True
            if direction == 'out':
                direction = 'self'  # Indicates self-transfer
                logger.debug(f"Transaction {tx_hash} is a self-transfer.")
            else:
                direction = 'in'
                logger.debug(f"Transaction {tx_hash} is incoming.")

        if involved:
            event_dict = {
                'timestamp': timestamp,
                'from': from_address_hex if from_address_hex else '',
                'to': to_address_hex if to_address_hex else '',
                'amount': amount,
                'token_symbol': 'EVMOS',
                'contract_address': '',
                'transaction_hash': tx_hash,
                'direction': direction,
                'method': method_name,
                'token_type': '',
                'comment': '',
                'type': '',
                'fee_amount': fee_amount,       # Ensure fee is included
                'fee_currency': fee_currency,   # Ensure fee is included
                'ethereum_tx_hash': eth_tx_hash if eth_tx_hash else ''  # Ensure Ethereum Tx Hash is set
            }
            # Process address naming
            event_dict['from'] = sanitize(rename_address(event_dict['from'], address_name_map))
            event_dict['to'] = sanitize(rename_address(event_dict['to'], address_name_map))
            logger.info(f"Processed EVM Transfer Event: {event_dict}")
            processed_events.append(event_dict)

    # Process EVM transaction events
    for event in events:
        if event.get('type') == 'tx_log':
            for attr in event.get('attributes', []):
                if attr.get('key') == 'txLog':
                    tx_log_value = attr.get('value')
                    try:
                        tx_log = json.loads(tx_log_value)
                        logger.debug(f"Decoded txLog: {tx_log}")
                        decoded_events = decode_evm_transfer_events(
                            tx_log,
                            timestamp,
                            hex_wallet_addresses,
                            tx_hash,
                            method_name,
                            contract_library,
                            address_name_map,
                            ibc_denom_library  # Pass ibc_denom_library here
                        )
                        if decoded_events:
                            for decoded_event in decoded_events:
                                # Ensure fee information is included if applicable
                                decoded_event['fee_amount'] = fee_amount
                                decoded_event['fee_currency'] = fee_currency
                                # Ensure Ethereum Tx Hash is set for decoded events
                                decoded_event['ethereum_tx_hash'] = tx_response.get('ethereum_tx_hash', '')
                                logger.info(f"Decoded EVM Transfer Event: {decoded_event}")
                                processed_events.append(decoded_event)
                    except Exception as e:
                        logger.error(f"Error parsing txLog in transaction {tx_hash}: {e}")
                        continue
    return processed_events


def process_cosmos_transaction(
    tx_response,
    tracked_addresses,
    address_name_map,
    ibc_denom_library,
    contract_library,
    fee_amount,
    fee_currency,
    validator_name_map
):
    processed_events = []
    tx_hash = tx_response['txhash']
    timestamp = tx_response['timestamp']

    # Cosmos transaction processing logic
    cosmos_events = process_cosmos_transactions(
        tx_response,
        tracked_addresses,
        address_name_map,
        ibc_denom_library,
        contract_library,
        validator_name_map  # Pass the mapping here
    )
    if cosmos_events:
        for cosmos_event in cosmos_events:
            # Ensure fee information is included if applicable
            cosmos_event['fee_amount'] = fee_amount
            cosmos_event['fee_currency'] = fee_currency
            # Ensure Ethereum Tx Hash is set for Cosmos events if available
            cosmos_event['ethereum_tx_hash'] = tx_response.get('ethereum_tx_hash', '')
            processed_events.append(cosmos_event)
    return processed_events

def process_wallets(wallet_addresses, max_transactions=None, api_url=None):
    """
    Processes the provided wallet addresses and returns the results.
    
    Parameters:
        wallet_addresses (list): List of wallet addresses (Bech32 or Hex).
        max_transactions (int, optional): Maximum number of transactions to fetch.
        api_url (str, optional): Custom API URL. If None, use the default.
        
    Returns:
        dict: Contains cointracking DataFrame.
    """
    if not wallet_addresses:
        raise ValueError("No wallet addresses provided.")

    tracked_addresses = []
    hex_wallet_addresses = []
    address_name_map = load_address_name_map()

    for addr in wallet_addresses:
        if is_bech32_address(addr):
            # Address is in Bech32 format
            bech32_addr = addr.lower()
            try:
                hex_addr = bech32_to_hex(bech32_addr)
                tracked_addresses.append(bech32_addr)
                hex_wallet_addresses.append(hex_addr)
                address_name_map[bech32_addr] = 'My Wallet'
                address_name_map[hex_addr] = 'My Wallet'
            except ValueError as e:
                print(f"Error converting Bech32 address {bech32_addr}: {e}")
        elif is_hex_address(addr):
            # Address is in Hex format
            hex_addr = addr.lower()
            try:
                bech32_addr = hex_to_bech32(hex_addr)
                tracked_addresses.append(bech32_addr)
                hex_wallet_addresses.append(hex_addr)
                address_name_map[bech32_addr] = 'My Wallet'
                address_name_map[hex_addr] = 'My Wallet'
            except ValueError as e:
                print(f"Error converting Hex address {hex_addr}: {e}")
        else:
            print(f"Invalid address format: {addr}. Please enter a valid Bech32 or Hex address.")

    if not tracked_addresses:
        raise ValueError("No valid wallet addresses provided after processing.")

    # Load data once
    method_sig_to_name = load_method_signatures()
    ibc_denom_library = load_ibc_denom_library()
    contract_library = load_contract_library()
    validator_name_map = load_validator_name_mapping('Validator_name_mapping.csv')

    # Fetch transactions
    transactions = []
    for address in tracked_addresses:
        print(f"Fetching transactions for address: {address}")
        txs = fetch_transactions(address, max_transactions, api_url)  # Pass api_url
        transactions.extend(txs)
        # Check if maximum transactions limit is reached
        if max_transactions and len(transactions) >= max_transactions:
            break

    if not transactions:
        print("No transactions found.")
        return {
            'cointracking_df': pd.DataFrame()
        }

    # Process transactions
    processed_transactions = process_transactions(
        transactions,
        tracked_addresses,
        hex_wallet_addresses,
        'transactions.xlsx',  # Placeholder, not used in web app
        method_sig_to_name,
        address_name_map,
        ibc_denom_library,
        contract_library,
        validator_name_map
    )

    if not processed_transactions:
        print("No processed transactions to map.")
        return {
            'cointracking_df': pd.DataFrame()
        }

    # Map to CoinTracking format
    exchange_str = ', '.join(tracked_addresses)
    cointracking_df = map_to_cointracking(
        processed_transactions,
        hex_wallet_addresses,
        contract_library,
        exchange_str
    )

    return {
        'cointracking_df': cointracking_df
    }


def main():
    """
    Main function to execute the transaction fetching and processing.
    """
    # Prompt the user for wallet addresses
    wallet_input = input("Please enter the Cosmos wallet address(es) (Bech32 or Hex, separated by commas or spaces): ").strip()

    # Split the input into individual addresses
    if ',' in wallet_input:
        input_addresses = [addr.strip() for addr in wallet_input.split(',')]
    else:
        input_addresses = [addr.strip() for addr in wallet_input.split()]

    if not input_addresses:
        print("No wallet addresses provided. Exiting.")
        return

    tracked_addresses = []
    hex_wallet_addresses = []
    address_name_map = load_address_name_map()

    for addr in input_addresses:
        if is_bech32_address(addr):
            # Address is in Bech32 format
            bech32_addr = addr.lower()
            try:
                hex_addr = bech32_to_hex(bech32_addr)
                tracked_addresses.append(bech32_addr)
                hex_wallet_addresses.append(hex_addr)
                address_name_map[bech32_addr] = 'My Wallet'
                address_name_map[hex_addr] = 'My Wallet'
            except ValueError as e:
                print(f"Error converting Bech32 address {bech32_addr}: {e}")
        elif is_hex_address(addr):
            # Address is in Hex format
            hex_addr = addr.lower()
            try:
                bech32_addr = hex_to_bech32(hex_addr)
                tracked_addresses.append(bech32_addr)
                hex_wallet_addresses.append(hex_addr)
                address_name_map[bech32_addr] = 'My Wallet'
                address_name_map[hex_addr] = 'My Wallet'
            except ValueError as e:
                print(f"Error converting Hex address {hex_addr}: {e}")
        else:
            print(f"Invalid address format: {addr}. Please enter a valid Bech32 or Hex address.")

    if not tracked_addresses:
        print("No valid wallet addresses provided after processing. Exiting.")
        return

    # Prompt the user for maximum number of transactions
    max_tx_input = input("Please enter the maximum number of transactions to fetch (leave blank for no limit): ").strip()
    if max_tx_input:
        try:
            max_transactions = int(max_tx_input)
            if max_transactions <= 0:
                print("Maximum transactions must be a positive integer. Exiting.")
                return
        except ValueError:
            print("Invalid input for maximum transactions. Please enter a positive integer. Exiting.")
            return
    else:
        max_transactions = None  # No limit

    # Load data once
    method_sig_to_name = load_method_signatures()
    ibc_denom_library = load_ibc_denom_library()
    contract_library = load_contract_library()
    validator_name_map = load_validator_name_mapping('Validator_name_mapping.csv')

    # Fetch transactions
    transactions = []
    for address in tracked_addresses:
        print(f"Fetching transactions for address: {address}")
        txs = fetch_transactions(address, max_transactions)
        transactions.extend(txs)
        # Check if maximum transactions limit is reached
        if max_transactions and len(transactions) >= max_transactions:
            break

    if not transactions:
        print("No transactions found.")
        return

    # Define output filename
    if len(tracked_addresses) == 1:
        address = tracked_addresses[0]
        # Sanitize the address for use in a filename
        sanitized_address = address.replace(' ', '').replace('/', '_').replace('\\', '_')[:10]  # Truncate to first 10 chars
        output_filename = f'transactions_{sanitized_address}.xlsx'
    else:
        output_filename = 'transactions_combined.xlsx'

    # Process transactions
    processed_transactions = process_transactions(
        transactions,
        tracked_addresses,
        hex_wallet_addresses,
        output_filename,
        method_sig_to_name,
        address_name_map,
        ibc_denom_library,
        contract_library,
        validator_name_map
    )

    # Check if there are any processed transactions
    if not processed_transactions:
        print("No processed transactions to map. Exiting.")
        return

    # Define exchange addresses as a comma-separated string
    exchange_str = ', '.join(tracked_addresses)

    # Map to CoinTracking format with exchange addresses
    cointracking_df = map_to_cointracking(
        processed_transactions,
        hex_wallet_addresses,
        contract_library,
        exchange_str
    )

    # Check if the DataFrame is empty
    if cointracking_df.empty:
        print("No data to write to Excel. The CoinTracking DataFrame is empty.")
    else:
        # Convert 'Date' column to datetime for sorting
        try:
            cointracking_df['Date'] = pd.to_datetime(cointracking_df['Date'], format='%d-%m-%Y %H:%M:%S')
        except Exception as e:
            print(f"Error converting 'Date' column to datetime: {e}")

        # Sort by 'Date' in ascending order
        cointracking_df.sort_values('Date', inplace=True)

        # Reset index after sorting
        cointracking_df.reset_index(drop=True, inplace=True)

        # Save to Excel
        try:
            cointracking_df.to_excel(output_filename, index=False, engine='openpyxl')
            print(f"Excel file '{output_filename}' generated successfully.")
        except PermissionError as pe:
            print(f"Permission Error: {pe}")
            print("Please ensure the Excel file is not open in any application and that you have write permissions to the directory.")
        except Exception as e:
            print(f"An error occurred while saving Excel file: {e}")

    # Output the processed transactions to a JSON file (Removed)
    # with open('processed_transactions.json', 'w', encoding='utf-8') as f:
    #     json.dump(processed_transactions, f, ensure_ascii=False, indent=4)
    # print("Processed transactions have been saved to 'processed_transactions.json'.")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        input("Press Enter to exit...")
