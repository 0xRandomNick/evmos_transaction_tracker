# cosmos_processor.py

from .utils import sanitize, rename_address
import datetime
import re
from .data_loader import load_ibc_denom_library

# Define the staking reward module address
STAKING_REWARD_MODULE = 'evmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd8974jnh'

def process_cosmos_transactions(
    tx_response,
    tracked_addresses,
    address_name_map,
    ibc_denom_library,
    contract_library,
    validator_name_map  # New parameter
):
    processed_events = []
    logs = tx_response.get('logs', [])
    timestamp = tx_response.get('timestamp')
    tx_hash = tx_response.get('txhash')

    tracked_addresses_set = set(addr.lower() for addr in tracked_addresses)
    staking_reward_sender = STAKING_REWARD_MODULE.lower()

    # Define mapping from event type to transaction type
    event_type_to_tx_type = {
        'delegate': 'Delegation',
        'undelegate': 'Undelegation',
        'unbond': 'Undelegation',  # Handle both 'undelegate' and 'unbond'
        'redelegate': 'Redelegation'
    }

    # Determine transaction types present in the logs
    transaction_types = set()
    for log in logs:
        events = log.get('events', [])
        for event in events:
            event_type = event.get('type')
            if event_type in event_type_to_tx_type:
                transaction_types.add(event_type_to_tx_type[event_type])

    # Build a mapping from msg_index to action
    msg_index_to_action = {}
    for log in logs:
        msg_index = log.get('msg_index')
        events = log.get('events', [])
        for event in events:
            if event.get('type') == 'message':
                attributes = parse_event_attributes(event.get('attributes', []))
                action = attributes.get('action')
                if action:
                    msg_index_to_action[msg_index] = action
                    break  # Assuming one 'message' event per log

    # Now process the events
    for log in logs:
        msg_index = log.get('msg_index')
        action = msg_index_to_action.get(msg_index)
        events = log.get('events', [])

        for event in events:
            event_type = event.get('type')
            attributes = parse_event_attributes(event.get('attributes', []))

            if event_type == 'transfer':
                sender = attributes.get('sender', '').lower()
                recipient = attributes.get('recipient', '').lower()
                amount_str = attributes.get('amount', '')

                # Check if this transfer is a staking reward
                is_staking_reward = False
                if sender == staking_reward_sender and recipient in tracked_addresses_set:
                    is_staking_reward = True

                # If the transaction is Delegation, Undelegation, or Redelegation,
                # and the transfer is from the staking reward module, treat it as staking reward
                if any(t in transaction_types for t in ['Delegation', 'Undelegation', 'Redelegation']) and is_staking_reward:
                    amount, denom = parse_amount(amount_str, ibc_denom_library)
                    if amount is not None:
                        event_dict = {
                            'timestamp': sanitize(timestamp),
                            'from': 'Staking Reward Module',
                            'to': rename_address(recipient, address_name_map),
                            'amount': amount,
                            'token_symbol': denom,
                            'contract_address': '',
                            'transaction_hash': tx_hash,
                            'direction': 'in',
                            'method': 'Staking Reward',
                            'token_type': '',
                            'comment': 'Staking reward',
                            'type': 'Staking Reward'
                        }
                        processed_events.append(event_dict)
                        print(f"Added staking reward event: {event_dict}")
                else:
                    # Regular transfer processing
                    transfers = extract_transfers(attributes)
                    for transfer in transfers:
                        sender_addr = transfer.get('sender', '').lower()
                        recipient_addr = transfer.get('recipient', '').lower()
                        amounts = transfer.get('amount', [])

                        for amt_str in amounts:
                            amount, denom = parse_amount(amt_str, ibc_denom_library)
                            if amount is None:
                                continue

                            direction = None
                            if sender_addr in tracked_addresses_set:
                                direction = 'out'
                            elif recipient_addr in tracked_addresses_set:
                                direction = 'in'

                            if direction:
                                event_dict = create_event_dict(
                                    timestamp,
                                    sender_addr,
                                    recipient_addr,
                                    amount,
                                    denom,
                                    tx_hash,
                                    direction,
                                    action if action else 'Transfer',
                                    '',
                                    '',
                                    address_name_map
                                )
                                # Debug statement
                                print(f"Adding transfer event: {event_dict}")
                                processed_events.append(event_dict)

            elif event_type in ['delegate', 'undelegate', 'redelegate', 'unbond']:
                # Extract delegation-related details
                mapped_type = event_type_to_tx_type.get(event_type, event_type.capitalize())

                if mapped_type == 'Redelegation':
                    # Extract source_validator and destination_validator
                    source_validator = attributes.get('source_validator')
                    destination_validator = attributes.get('destination_validator')
                    amount_str = attributes.get('amount')
                    if not amount_str:
                        continue
                    amount, denom = parse_amount(amount_str, ibc_denom_library)
                    if amount is None:
                        continue

                    # Get validator names from the mapping; default to addresses if not found
                    source_validator_name = validator_name_map.get(source_validator.lower(), source_validator) if source_validator else 'Unknown Source Validator'
                    destination_validator_name = validator_name_map.get(destination_validator.lower(), destination_validator) if destination_validator else 'Unknown Destination Validator'

                    # Construct the comment without completion_time
                    if source_validator_name and destination_validator_name:
                        comment = f'Redelegated from {source_validator_name} to {destination_validator_name}'
                    else:
                        comment = f'Redelegation between validators'

                    # Update the 'to' field with the validator names
                    to_field = f'Validators: {source_validator_name} -> {destination_validator_name}' if source_validator_name and destination_validator_name else 'Validators: Unknown'

                    event_dict = {
                        'timestamp': sanitize(timestamp),
                        'from': 'My Wallet',
                        'to': to_field,
                        'amount': amount,
                        'token_symbol': denom,
                        'contract_address': '',
                        'transaction_hash': tx_hash,
                        'direction': 'out',
                        'method': action if action else mapped_type,
                        'token_type': '',
                        'comment': comment,  # No completion_time included
                        'type': mapped_type
                    }
                    processed_events.append(event_dict)
                    print(f"Added {mapped_type} event: {event_dict}")

                elif mapped_type == 'Undelegation':
                    # Extract validator
                    validator = attributes.get('validator') or attributes.get('validator_address')
                    amount_str = attributes.get('amount')
                    if not amount_str:
                        continue
                    amount, denom = parse_amount(amount_str, ibc_denom_library)
                    if amount is None:
                        continue

                    # Extract completion_time for Undelegation
                    completion_time = attributes.get('completion_time', '')

                    # Get the validator name from the mapping; default to address if not found
                    validator_name = validator_name_map.get(validator.lower(), validator) if validator else 'Unknown Validator'

                    # Construct the comment with correct grammar
                    if validator_name:
                        comment = f'Undelegation from {validator_name}'
                    else:
                        comment = f'Undelegation from Unknown Validator'

                    if completion_time:
                        formatted_time = format_completion_time(completion_time)
                        comment += f' | Completion Time: {formatted_time}'

                    # Update the 'to' field with the validator name
                    to_field = f'Validator: {validator_name}' if validator_name else 'Validator: Unknown'

                    event_dict = {
                        'timestamp': sanitize(timestamp),
                        'from': 'My Wallet',
                        'to': to_field,
                        'amount': amount,
                        'token_symbol': denom,
                        'contract_address': '',
                        'transaction_hash': tx_hash,
                        'direction': 'out',
                        'method': action if action else mapped_type,
                        'token_type': '',
                        'comment': comment,
                        'type': mapped_type
                    }
                    processed_events.append(event_dict)
                    print(f"Added {mapped_type} event: {event_dict}")

                elif mapped_type == 'Delegation':
                    # Extract validator
                    validator = attributes.get('validator') or attributes.get('validator_address')
                    amount_str = attributes.get('amount')
                    if not amount_str:
                        continue
                    amount, denom = parse_amount(amount_str, ibc_denom_library)
                    if amount is None:
                        continue

                    # Get the validator name from the mapping; default to address if not found
                    validator_name = validator_name_map.get(validator.lower(), validator) if validator else 'Unknown Validator'

                    # Construct the comment
                    if validator_name:
                        comment = f'Delegation to {validator_name}'
                    else:
                        comment = f'Delegation to Unknown Validator'

                    # Update the 'to' field with the validator name
                    to_field = f'Validator: {validator_name}' if validator_name else 'Validator: Unknown'

                    event_dict = {
                        'timestamp': sanitize(timestamp),
                        'from': 'My Wallet',
                        'to': to_field,
                        'amount': amount,
                        'token_symbol': denom,
                        'contract_address': '',
                        'transaction_hash': tx_hash,
                        'direction': 'out',
                        'method': action if action else mapped_type,
                        'token_type': '',
                        'comment': comment,
                        'type': mapped_type
                    }
                    processed_events.append(event_dict)
                    print(f"Added {mapped_type} event: {event_dict}")

                else:
                    # Handle other mapped types if any
                    pass

            # Omit 'withdraw_rewards' and other unrelated events
            elif event_type == 'withdraw_rewards':
                continue

            else:
                # Process other event types if necessary
                pass


    # After processing all events, remove any duplicate events based on transaction_hash and type
    unique_transactions = []
    seen = set()
    for event in processed_events:
        identifier = (event['transaction_hash'], event['type'], event['method'], event['amount'])
        if identifier not in seen:
            seen.add(identifier)
            unique_transactions.append(event)
        else:
            print(f"Duplicate event detected and skipped: {event}")

    return unique_transactions


def parse_event_attributes(attributes):
    attr_dict = {}
    for attr in attributes:
        key = attr.get('key')
        value = attr.get('value')
        if key and value:
            attr_dict[key] = value
    return attr_dict


def extract_transfers(attributes):
    transfers = []
    sender = attributes.get('sender', '')
    recipient = attributes.get('recipient', '')
    amount = attributes.get('amount', '').split(',')

    if sender and recipient and amount:
        transfers.append({'sender': sender, 'recipient': recipient, 'amount': amount})

    return transfers


def parse_amount(amount_str, ibc_denom_library):
    try:
        # Extract numeric amount and denom
        match = re.match(r'(?P<amount>\d+)(?P<denom>.+)', amount_str)
        if not match:
            return None, None
        amount_value = int(match.group('amount'))
        denom = match.group('denom')

        # Check if denom is a known denom
        if denom == 'aevmos':
            token_symbol = 'EVMOS'
            amount = amount_value / 1e18
        elif denom == 'uatom':
            token_symbol = 'ATOM'
            amount = amount_value / 1e6
        elif denom == 'uosmo':
            token_symbol = 'OSMO'
            amount = amount_value / 1e6
        elif denom.startswith('ibc/'):
            # Look up in IBC denom library
            denom_info = ibc_denom_library.get(denom)
            if denom_info:
                if isinstance(denom_info, dict):
                    token_symbol = denom_info['Symbol']
                    exponent = denom_info['Exponent']
                else:
                    # If denom_info is a string (symbol), assume default exponent
                    token_symbol = denom_info
                    exponent = 6  # Default exponent
            else:
                token_symbol = denom  # Use denom if not found
                exponent = 6  # Default exponent
            amount = amount_value / (10 ** exponent)
        else:
            token_symbol = denom  # Use denom as token symbol
            amount = amount_value / 1e6  # Default to 6 decimals
        return amount, token_symbol
    except Exception as e:
        print(f"Error parsing amount '{amount_str}': {e}")
        return None, None


def create_event_dict(timestamp, sender, recipient, amount, denom, tx_hash, direction,
                      method, comment, tx_type, address_name_map):
    event = {
        'timestamp': sanitize(timestamp),
        'from': sanitize(rename_address(sender, address_name_map)),
        'to': sanitize(rename_address(recipient, address_name_map)),
        'amount': amount,
        'token_symbol': denom,
        'contract_address': '',
        'transaction_hash': tx_hash,
        'direction': direction,
        'method': method,
        'token_type': '',
        'comment': comment,
        'type': tx_type
    }
    return event


def format_completion_time(completion_time):
    if completion_time:
        try:
            completion_time_dt = datetime.datetime.fromisoformat(completion_time.replace('Z', '+00:00'))
            return completion_time_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception as e:
            print(f"Error formatting completion time '{completion_time}': {e}")
    return ''
