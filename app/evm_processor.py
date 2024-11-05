import base64
import json
from eth_utils import to_checksum_address
from .utils import sanitize, rename_address

# Load the address-to-comment mapping
address_comment_map = {
    '0x3eb0fffa1470cdd3725b9eb29aded2736144b078': 'Revert LP Incentives',
    # Add more addresses and comments as needed
}

# Event signatures
TRANSFER_SIGNATURE = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
WITHDRAWAL_SIGNATURE = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65'
INCREASE_LIQUIDITY_SIGNATURE = '0x3067048beee31b25b2f1681f88dac838c8bba36af25bfb2b7cf7473a5847e35f'
DECREASE_LIQUIDITY_SIGNATURE = '0x26f6a048ee9138f2c0ce266f322cb99228e8d619ae2bff30c67f8dcf9d2377b4'
IBC_TRANSFER_SIGNATURE = '0xc01eca5e742fe6641c4be501c2bebf224472f69176a0552e87e30147a6411303'
WEVMOS_CONTRACT_ADDRESS = '0xd4949664cd82660aae99bedc034a0dea8a0bd517'

# Map event signatures to handler functions
EVENT_SIGNATURES = {
    TRANSFER_SIGNATURE: 'handle_transfer_event',
    WITHDRAWAL_SIGNATURE: 'handle_withdrawal_event',
    INCREASE_LIQUIDITY_SIGNATURE: 'handle_increase_liquidity_event',
    DECREASE_LIQUIDITY_SIGNATURE: 'handle_decrease_liquidity_event',
    IBC_TRANSFER_SIGNATURE: 'handle_ibc_transfer_event',
}

def decode_evm_transfer_events(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    decoded_events = []

    topics = tx_log.get('topics', [])
    if not topics:
        return []
    event_signature = topics[0].lower()

    handler_name = EVENT_SIGNATURES.get(event_signature, None)

    if handler_name:
        handler_function = globals()[handler_name]
        # Pass ibc_denom_library to the handler function
        events = handler_function(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library)
        decoded_events.extend(events)
    else:
        # Unhandled event
        pass

    return decoded_events

def handle_transfer_event(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    decoded_events = []

    topics = tx_log.get('topics', [])
    from_address = to_checksum_address('0x' + topics[1][-40:]) if len(topics) > 1 else None
    to_address = to_checksum_address('0x' + topics[2][-40:]) if len(topics) > 2 else None

    # Decode the amount
    data_field = tx_log.get('data')
    if data_field:
        try:
            data_bytes = base64.b64decode(data_field)
            amount = int.from_bytes(data_bytes, byteorder='big')
        except Exception:
            try:
                data_bytes = bytes.fromhex(data_field[2:] if data_field.startswith('0x') else data_field)
                amount = int.from_bytes(data_bytes, byteorder='big')
            except Exception as e:
                print(f"Error decoding amount in txLog for transaction {transaction_hash}: {e}")
                return []
    else:
        print(f"No data field found in txLog for transaction {transaction_hash}")
        return []

    # Extract the contract address
    contract_address = to_checksum_address(tx_log['address'])

    # Get token info
    token_info = contract_library.get(contract_address, None)
    if token_info is None:
        # Contract address not found in library
        token_name = 'Unknown'
        token_symbol = contract_address  # Use contract address as token symbol
        token_decimals = 18  # Default decimals
        token_type = ''
    else:
        token_name = sanitize(token_info['Token Name'])
        token_symbol = sanitize(token_info['Token Symbol'])
        token_decimals = token_info['Token Decimals']
        token_type = token_info.get('Token Type', '')

    # Adjust the amount based on decimals
    adjusted_amount = amount / (10 ** token_decimals)

    # Determine direction
    if from_address and from_address.lower() in hex_wallet_addresses:
        direction = 'out'
    elif to_address and to_address.lower() in hex_wallet_addresses:
        direction = 'in'
    else:
        direction = 'other'  # Not involving our wallet

    # Record the event if it involves our wallet
    if direction != 'other':
        # Initialize comment
        comment = ''

        # Check if the 'from' address is in our address_comment_map
        if direction == 'in' and from_address and from_address.lower() in address_comment_map:
            comment = address_comment_map[from_address.lower()]

        # Create the event dictionary
        event = {
            'timestamp': sanitize(timestamp),
            'from': sanitize(rename_address(from_address, address_name_map)),
            'to': sanitize(rename_address(to_address, address_name_map)),
            'amount': sanitize(adjusted_amount),
            'token_symbol': sanitize(token_symbol),
            'contract_address': sanitize(contract_address),
            'transaction_hash': transaction_hash,
            'direction': direction,
            'method': method_name,
            'token_type': token_type,
            'comment': comment
        }
        decoded_events.append(event)

    return decoded_events

def handle_withdrawal_event(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    decoded_events = []
    contract_address = to_checksum_address(tx_log['address'])
    if contract_address.lower() == WEVMOS_CONTRACT_ADDRESS:
        # Decode the amount
        data_field = tx_log.get('data')
        if data_field:
            try:
                data_bytes = base64.b64decode(data_field)
                amount = int.from_bytes(data_bytes, byteorder='big')
            except Exception:
                try:
                    data_bytes = bytes.fromhex(data_field[2:] if data_field.startswith('0x') else data_field)
                    amount = int.from_bytes(data_bytes, byteorder='big')
                except Exception as e:
                    print(f"Error decoding amount in txLog for transaction {transaction_hash}: {e}")
                    return []
        else:
            print(f"No data field found in txLog for transaction {transaction_hash}")
            return []

        # Adjust the amount (WEVMOS has 18 decimals)
        adjusted_amount = amount / 1e18
        token_symbol = 'EVMOS'

        # Record the event as an incoming EVMOS transfer
        event = {
            'timestamp': sanitize(timestamp),
            'from': 'WEVMOS Contract',
            'to': 'My Wallet',
            'amount': sanitize(adjusted_amount),
            'token_symbol': token_symbol,
            'contract_address': sanitize(contract_address),
            'transaction_hash': transaction_hash,
            'direction': 'in',
            'method': method_name,
            'token_type': '',
            'comment': 'Unwrapped WEVMOS'
        }
        decoded_events.append(event)

    return decoded_events

def handle_increase_liquidity_event(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    return handle_liquidity_event('IncreaseLiquidity', 'in', tx_log, timestamp, transaction_hash, method_name, address_name_map)

def handle_decrease_liquidity_event(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    return handle_liquidity_event('DecreaseLiquidity', 'out', tx_log, timestamp, transaction_hash, method_name, address_name_map)

def handle_liquidity_event(event_name, direction, tx_log, timestamp, transaction_hash, method_name, address_name_map):
    print(f"Detected {event_name} event")
    topics = tx_log.get('topics', [])
    if len(topics) < 2:
        print(f"Not enough topics in {event_name} event for transaction {transaction_hash}")
        return []
    tokenId_hex = topics[1]
    tokenId = int(tokenId_hex, 16)
    print(f"Token ID: {tokenId}")
    data_field = tx_log.get('data')
    if data_field:
        try:
            # Base64 decoding
            missing_padding = len(data_field) % 4
            if missing_padding:
                data_field += '=' * (4 - missing_padding)
            data_bytes = base64.b64decode(data_field)
            print(f"Data bytes length: {len(data_bytes)}")
            if len(data_bytes) >= 96:
                # Extract parameters
                liquidity_bytes = data_bytes[0:32]
                amount0_bytes = data_bytes[32:64]
                amount1_bytes = data_bytes[64:96]
                liquidity = int.from_bytes(liquidity_bytes, byteorder='big')
                amount0 = int.from_bytes(amount0_bytes, byteorder='big')
                amount1 = int.from_bytes(amount1_bytes, byteorder='big')
                print(f"Liquidity: {liquidity}")
                print(f"Amount0: {amount0}")
                print(f"Amount1: {amount1}")
                adjusted_liquidity = liquidity / 1e12  # Adjust if needed
                # Set 'from' and 'to' based on direction
                if direction == 'in':
                    from_address = 'Liquidity Pool'
                    to_address = 'My Wallet'
                else:
                    from_address = 'My Wallet'
                    to_address = 'Liquidity Pool'
                # Create event
                event = {
                    'timestamp': sanitize(timestamp),
                    'from': from_address,
                    'to': to_address,
                    'amount': sanitize(adjusted_liquidity),
                    'token_symbol': f'LP-{tokenId}',
                    'contract_address': '',
                    'transaction_hash': transaction_hash,
                    'direction': direction,
                    'method': method_name,
                    'token_type': '',
                    'comment': ''
                }
                print(f"Added event: {event}")
                return [event]
            else:
                print(f"Data length too short for {event_name} event in transaction {transaction_hash}")
                return []
        except Exception as e:
            print(f"Error decoding data in {event_name} event for transaction {transaction_hash}: {e}")
            return []
    else:
        print(f"No data field found in {event_name} event for transaction {transaction_hash}")
        return []

def handle_ibc_transfer_event(tx_log, timestamp, hex_wallet_addresses, transaction_hash, method_name, contract_library, address_name_map, ibc_denom_library):
    # Handle IBCTransfer event
    decoded_events = []

    # From the description, topics contain:
    # topics[1]: sender (indexed)
    # topics[2]: receiver (indexed, hashed)
    topics = tx_log.get('topics', [])
    if len(topics) < 3:
        print(f"Not enough topics in IBCTransfer event for transaction {transaction_hash}")
        return []

    # Get the sender address
    sender_address = to_checksum_address('0x' + topics[1][-40:]) if len(topics) > 1 else None
    # Receiver is hashed, cannot extract directly

    # Decode the data field
    data_field = tx_log.get('data')
    if data_field:
        try:
            # Base64 decoding
            missing_padding = len(data_field) % 4
            if missing_padding:
                data_field += '=' * (4 - missing_padding)
            data_bytes = base64.b64decode(data_field)
        except Exception:
            try:
                data_bytes = bytes.fromhex(data_field[2:] if data_field.startswith('0x') else data_field)
            except Exception as e:
                print(f"Error decoding data in IBCTransfer event for transaction {transaction_hash}: {e}")
                return []
    else:
        print(f"No data field found in IBCTransfer event for transaction {transaction_hash}")
        return []

    try:
        # ABI decoding based on the function signature
        # The data contains dynamic types (strings), so the first 32 bytes are offsets to the actual data

        # Get the offsets
        offset_source_port = int.from_bytes(data_bytes[0:32], byteorder='big')
        offset_source_channel = int.from_bytes(data_bytes[32:64], byteorder='big')
        offset_denom = int.from_bytes(data_bytes[64:96], byteorder='big')
        amount_bytes = data_bytes[96:128]
        offset_memo = int.from_bytes(data_bytes[128:160], byteorder='big')

        amount = int.from_bytes(amount_bytes, byteorder='big')

        # Extract denom
        denom = decode_abi_string(data_bytes, offset_denom)

        # Use ibc_denom_library to get token symbol and decimals
        denom_info = ibc_denom_library.get(denom, {})
        token_symbol = denom_info.get('Symbol', denom)
        token_decimals = int(denom_info.get('Exponent', 6))  # Default to 6 decimals if not found

        # Determine direction
        if sender_address and sender_address.lower() in hex_wallet_addresses:
            direction = 'out'
            to_address = 'IBC Destination'
            from_address = 'My Wallet'
        else:
            direction = 'in'
            to_address = 'My Wallet'
            from_address = 'IBC Source'

        # Adjust amount based on decimals
        adjusted_amount = amount / (10 ** token_decimals)

        # Create event
        event = {
            'timestamp': sanitize(timestamp),
            'from': sanitize(rename_address(from_address, address_name_map)),
            'to': to_address,
            'amount': sanitize(adjusted_amount),
            'token_symbol': sanitize(token_symbol),
            'contract_address': '',
            'transaction_hash': transaction_hash,
            'direction': direction,
            'method': method_name,
            'token_type': '',
            'comment': 'IBC Transfer'
        }
        decoded_events.append(event)
    except Exception as e:
        print(f"Error decoding IBCTransfer event for transaction {transaction_hash}: {e}")
        return []

    return decoded_events


def decode_abi_string(data_bytes, offset):
    # The offset is relative to the start of the data
    # Read the length of the string (32 bytes)
    string_length = int.from_bytes(data_bytes[offset:offset+32], byteorder='big')
    # Read the string bytes
    string_bytes = data_bytes[offset+32:offset+32+string_length]
    decoded_string = string_bytes.decode('utf-8')
    return decoded_string

