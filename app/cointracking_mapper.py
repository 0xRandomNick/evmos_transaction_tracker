# cointracking_mapper.py

import pandas as pd
import datetime
import logging

# Set up logging to display debug messages in the console
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def map_to_cointracking(processed_transactions, hex_wallet_addresses, contract_library, exchange_str):
    """
    Map processed transactions to CoinTracking format.

    Parameters:
        processed_transactions (list): List of processed transaction dictionaries.
        hex_wallet_addresses (list): List of hex wallet addresses.
        contract_library (dict): Dictionary of contract addresses and their details.
        exchange_str (str): Comma-separated string of wallet addresses to populate "Wallet Address".

    Returns:
        pd.DataFrame: DataFrame in CoinTracking format.
    """
    df = pd.DataFrame(processed_transactions)
    
    # Debug: Print DataFrame columns and a sample of data
    print(f"DEBUG: DataFrame columns: {df.columns.tolist()}")
    print(f"DEBUG: DataFrame sample data:\n{df.head()}")

    if df.empty:
        logging.info("No transactions to map to CoinTracking format.")
        return pd.DataFrame()

    logging.info(f"Mapping {len(df)} transactions to CoinTracking format.")

    # Define CoinTracking columns
    columns = [
        'Type', 'Buy Amount', 'Buy Cur.', 'Sell Amount', 'Sell Cur.',
        'Fee Amount', 'Fee Cur.', 'Wallet Address',
        'Trade Group', 'Comment', 'Date', 'Liquidity pool',
        'Tx-ID', 'Ethereum Tx Hash', 'Transfer From', 'Transfer To'
    ]

    # Ensure all required columns are present in the DataFrame
    for col in columns:
        if col not in df.columns:
            df[col] = ''

    # Sort and group transactions by 'transaction_hash'
    df.sort_values('transaction_hash', inplace=True)
    grouped = df.groupby('transaction_hash')

    cointracking_data = []

    for tx_hash, tx_events in grouped:
        tx_events = tx_events.copy()
        timestamp = tx_events.iloc[0]['timestamp']
        try:
            date_str = datetime.datetime.fromisoformat(
                timestamp.replace('Z', '+00:00')
            ).strftime('%d-%m-%Y %H:%M:%S')
        except Exception as e:
            logging.error(f"Error parsing timestamp '{timestamp}' for transaction {tx_hash}: {e}")
            date_str = 'Unknown Date'

        tx_id = tx_hash  # Retain Cosmos tx_hash as Tx-ID
        eth_tx_hash = tx_events['ethereum_tx_hash'].iloc[0] if 'ethereum_tx_hash' in tx_events.columns else ''

        # Extract fee data for this transaction
        fee_amount = tx_events['fee_amount'].iloc[0] if 'fee_amount' in tx_events.columns else None
        
        # **Modified Fee Currency Assignment**
        try:
            fee_currency = 'EVMOS' if fee_amount and float(fee_amount) > 0 else None
        except (ValueError, TypeError):
            fee_currency = None

        # Debugging statements to check fee assignment
        print(f"DEBUG: Processing transaction group {tx_hash}")
        print(f"DEBUG: fee_amounts: {tx_events['fee_amount'].tolist() if 'fee_amount' in tx_events.columns else 'N/A'}")
        print(f"DEBUG: fee_currencies: {tx_events['fee_currency'].tolist() if 'fee_currency' in tx_events.columns else 'N/A'}")
        print(f"DEBUG: Extracted fee - Amount: {fee_amount}, Currency: {fee_currency}")  # Updated to show hardcoded currency
        print(f"DEBUG: Ethereum Tx Hash: {eth_tx_hash}")

        if fee_amount is None:
            logging.debug(f"No fee found for transaction {tx_id}. Fee amount: {fee_amount}")
        else:
            logging.debug(f"Fee found for transaction {tx_id}. Fee amount: {fee_amount}, Fee currency: {fee_currency}")

        # Identify transaction types within the grouped events
        transaction_types = set(tx_events['type'])

        # Initialize fee assignment flag
        fee_assigned = False

        # Handle 'Failed Transaction' type
        if 'Failed Transaction' in transaction_types:
            event = tx_events[tx_events['type'] == 'Failed Transaction'].iloc[0]
            event_method = event.get('method', 'Unknown')
            event_comment = event.get('comment', '')
            from_address = event.get('from', '')
            to_address = event.get('to', '')

            # Assign fee only if not yet assigned and fee exists
            if not fee_assigned and fee_amount and fee_currency:
                current_fee_amount = fee_amount
                current_fee_currency = fee_currency
                fee_assigned = True
            else:
                current_fee_amount = ''
                current_fee_currency = ''

            ct_row = create_ct_row(
                'Failed Transaction',
                '',
                '',
                '',
                '',
                date_str,
                event_method,
                event_comment,
                tx_id,
                eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                from_address=from_address,
                to_address=to_address,
                fee_amount=current_fee_amount,
                fee_currency=current_fee_currency
            )
            cointracking_data.append(ct_row)
            logging.debug(f"Added failed transaction row for {tx_id}")

        # Handle 'Staking Reward' type
        if 'Staking Reward' in transaction_types:
            staking_reward_events = tx_events[tx_events['type'] == 'Staking Reward']
            for _, event in staking_reward_events.iterrows():
                if not fee_assigned and fee_amount and fee_currency:
                    current_fee_amount = fee_amount
                    current_fee_currency = fee_currency
                    fee_assigned = True
                else:
                    current_fee_amount = ''
                    current_fee_currency = ''

                ct_row = create_ct_row(
                    'Income',
                    event['amount'],
                    event['token_symbol'],
                    '',
                    '',
                    date_str,
                    event.get('method', 'Staking Reward'),
                    event.get('comment', ''),
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address=event.get('from', ''),
                    to_address=event.get('to', ''),
                    fee_amount=current_fee_amount,
                    fee_currency=current_fee_currency
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added staking reward row for {tx_id}")

        # Handle 'Delegation', 'Undelegation', 'Redelegation' types
        staking_transactions = ['Delegation', 'Undelegation', 'Redelegation']
        for tx_type in staking_transactions:
            if tx_type in transaction_types:
                staking_events = tx_events[tx_events['type'] == tx_type]
                for _, event in staking_events.iterrows():
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    transaction_type = tx_type
                    method_name = event.get('method', tx_type)
                    comment = event.get('comment', '')

                    ct_row = create_ct_row(
                        transaction_type,
                        event['amount'] if event['direction'] == 'in' else '',
                        event['token_symbol'] if event['direction'] == 'in' else '',
                        event['amount'] if event['direction'] == 'out' else '',
                        event['token_symbol'] if event['direction'] == 'out' else '',
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=event.get('from', ''),
                        to_address=event.get('to', ''),
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added {transaction_type} transaction row for {tx_id}")

        # Handle 'Fee' Transactions
        if 'Fee' in transaction_types:
            fee_events = tx_events[tx_events['type'] == 'Fee']
            for _, fee_event in fee_events.iterrows():
                if not fee_assigned and fee_amount and fee_currency:
                    current_fee_amount = fee_amount
                    current_fee_currency = fee_currency
                    fee_assigned = True
                else:
                    current_fee_amount = ''
                    current_fee_currency = ''

                ct_row = create_ct_row(
                    'Fee',
                    '',
                    '',
                    fee_event['amount'],
                    fee_event['token_symbol'],
                    date_str,
                    fee_event.get('method', 'Fee'),
                    fee_event.get('comment', ''),
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address=fee_event.get('from', ''),
                    to_address=fee_event.get('to', ''),
                    fee_amount=current_fee_amount,
                    fee_currency=current_fee_currency
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added fee row for {tx_id}")

        # Handle 'Deposit' type
        if 'Deposit' in transaction_types:
            deposit_events = tx_events[tx_events['type'] == 'Deposit']
            for _, event in deposit_events.iterrows():
                if not fee_assigned and fee_amount and fee_currency:
                    current_fee_amount = fee_amount
                    current_fee_currency = fee_currency
                    fee_assigned = True
                else:
                    current_fee_amount = ''
                    current_fee_currency = ''

                ct_row = create_ct_row(
                    'Deposit',
                    event['amount'],
                    event['token_symbol'],
                    '',
                    '',
                    date_str,
                    event.get('method', 'Deposit'),
                    event.get('comment', ''),
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address=event.get('from', ''),
                    to_address=event.get('to', ''),
                    fee_amount=current_fee_amount,
                    fee_currency=current_fee_currency
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added Deposit row for {tx_id} with token {event['token_symbol']}")

        # Handle 'Trade' type
        if 'Trade' in transaction_types:
            trade_events = tx_events[tx_events['type'] == 'Trade']
            for _, event in trade_events.iterrows():
                if not fee_assigned and fee_amount and fee_currency:
                    current_fee_amount = fee_amount
                    current_fee_currency = fee_currency
                    fee_assigned = True
                else:
                    current_fee_amount = ''
                    current_fee_currency = ''

                ct_row = create_ct_row(
                    'Trade',
                    event['buy_amount'],
                    event['buy_currency'],
                    event['sell_amount'],
                    event['sell_currency'],
                    date_str,
                    event.get('method', 'Trade'),
                    event.get('comment', ''),
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address=event.get('from', ''),
                    to_address=event.get('to', ''),
                    fee_amount=current_fee_amount,
                    fee_currency=current_fee_currency
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added Trade row for {tx_id}: Buy {event['buy_amount']} {event['buy_currency']} for Sell {event['sell_amount']} {event['sell_currency']}")

        # Handle other transaction types
        # Exclude staking-related and fee-related transfers to prevent duplication
        other_events = tx_events[~tx_events['type'].isin(['Delegation', 'Undelegation', 'Redelegation', 'Staking Reward', 'Fee', 'Failed Transaction'])]
        if not other_events.empty:
            # Extract method_name and comment from the first event in the transaction
            first_event = other_events.iloc[0]
            method_name = first_event.get('method', '')
            comment = first_event.get('comment', '')

            tokens = other_events['token_symbol'].unique()
            token_summary = []

            # Extract 'from' and 'to' addresses for the transaction
            from_addresses = other_events['from'].unique()
            to_addresses = other_events['to'].unique()

            # For simplicity, join multiple addresses if there are more than one
            from_address = ', '.join(filter(None, from_addresses))
            to_address = ', '.join(filter(None, to_addresses))

            for token in tokens:
                token_events = other_events[other_events['token_symbol'] == token]
                amount_in = token_events[token_events['direction'] == 'in']['amount'].sum()
                amount_out = token_events[token_events['direction'] == 'out']['amount'].sum()
                net_amount = amount_in - amount_out
                token_summary.append({
                    'token': token,
                    'net_amount': net_amount,
                    'amount_in': amount_in,
                    'amount_out': amount_out,
                    'contract_address': token_events.iloc[0].get('contract_address', ''),
                })

            net_positive_tokens = [t for t in token_summary if t['net_amount'] > 0]
            net_negative_tokens = [t for t in token_summary if t['net_amount'] < 0]

            transaction_type = classify_transaction(net_positive_tokens, net_negative_tokens)

            if transaction_type == 'Provide Liquidity':
                for token_info in net_negative_tokens:
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    ct_row = create_ct_row(
                        'Provide Liquidity',
                        '',
                        '',
                        abs(token_info['net_amount']),
                        token_info['token'],
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=from_address,
                        to_address=to_address,
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added Provide Liquidity row for {tx_id} with token {token_info['token']}")
                for token_info in net_positive_tokens:
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    ct_row = create_ct_row(
                        'Received LP Token',
                        token_info['net_amount'],
                        token_info['token'],
                        '',
                        '',
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=from_address,
                        to_address=to_address,
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added Received LP Token row for {tx_id} with token {token_info['token']}")

            elif transaction_type == 'Remove Liquidity':
                for token_info in net_negative_tokens:
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    ct_row = create_ct_row(
                        'Return LP Token',
                        '',
                        '',
                        abs(token_info['net_amount']),
                        token_info['token'],
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=from_address,
                        to_address=to_address,
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added Return LP Token row for {tx_id} with token {token_info['token']}")
                for token_info in net_positive_tokens:
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    ct_row = create_ct_row(
                        'Remove Liquidity',
                        token_info['net_amount'],
                        token_info['token'],
                        '',
                        '',
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=from_address,
                        to_address=to_address,
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added Remove Liquidity row for {tx_id} with token {token_info['token']}")

            elif transaction_type == 'Trade':
                for neg_token in net_negative_tokens:
                    for pos_token in net_positive_tokens:
                        if not fee_assigned and fee_amount and fee_currency:
                            current_fee_amount = fee_amount
                            current_fee_currency = fee_currency
                            fee_assigned = True
                        else:
                            current_fee_amount = ''
                            current_fee_currency = ''

                        ct_row = create_ct_row(
                            'Trade',
                            pos_token['net_amount'],
                            pos_token['token'],
                            abs(neg_token['net_amount']),
                            neg_token['token'],
                            date_str,
                            method_name,
                            comment,
                            tx_id,
                            eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                            from_address=from_address,
                            to_address=to_address,
                            fee_amount=current_fee_amount,
                            fee_currency=current_fee_currency
                        )
                        cointracking_data.append(ct_row)
                        logging.debug(f"Added Trade row for {tx_id} swapping {neg_token['token']} to {pos_token['token']}")

            elif transaction_type in ['Deposit', 'Withdrawal']:
                for token_info in (net_positive_tokens if transaction_type == 'Deposit' else net_negative_tokens):
                    if not fee_assigned and fee_amount and fee_currency:
                        current_fee_amount = fee_amount
                        current_fee_currency = fee_currency
                        fee_assigned = True
                    else:
                        current_fee_amount = ''
                        current_fee_currency = ''

                    ct_row = create_ct_row(
                        transaction_type,
                        token_info['net_amount'] if transaction_type == 'Deposit' else '',
                        token_info['token'] if transaction_type == 'Deposit' else '',
                        abs(token_info['net_amount']) if transaction_type == 'Withdrawal' else '',
                        token_info['token'] if transaction_type == 'Withdrawal' else '',
                        date_str,
                        method_name,
                        comment,
                        tx_id,
                        eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                        from_address=from_address,
                        to_address=to_address,
                        fee_amount=current_fee_amount,
                        fee_currency=current_fee_currency
                    )
                    cointracking_data.append(ct_row)
                    logging.debug(f"Added {transaction_type} row for {tx_id} with token {token_info['token']}")

            else:
                if not fee_assigned and fee_amount and fee_currency:
                    current_fee_amount = fee_amount
                    current_fee_currency = fee_currency
                    fee_assigned = True
                else:
                    current_fee_amount = ''
                    current_fee_currency = ''

                ct_row = create_ct_row(
                    'Other Transaction',
                    '', '', '', '',
                    date_str,
                    method_name,
                    'Unclassified transaction',
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address=from_address,
                    to_address=to_address,
                    fee_amount=current_fee_amount,
                    fee_currency=current_fee_currency
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added Other Transaction row for {tx_id}")

    # After processing all known transaction types, check if fee is still unassigned
        # This handles transactions like "Approve" where no entries were mapped
        if not any(event['type'] in ['Failed Transaction', 'Income', 'Delegation', 'Undelegation', 'Redelegation', 'Fee', 'Deposit', 'Trade', 'Provide Liquidity', 'Remove Liquidity'] for event in tx_events.to_dict('records')):
            if fee_amount and fee_currency and not fee_assigned:
                ct_row = create_ct_row(
                    'Fee',
                    '',
                    '',
                    fee_amount,
                    fee_currency,
                    date_str,
                    method_name,
                    'Fee for untracked transaction type (e.g., Approve)',
                    tx_id,
                    eth_tx_hash=eth_tx_hash,  # Always pass Ethereum Tx Hash
                    from_address='Fee Collector',
                    to_address='My Wallet',
                    fee_amount='',          # Fee already represented by this entry
                    fee_currency=''
                )
                cointracking_data.append(ct_row)
                logging.debug(f"Added standalone Fee row for transaction {tx_id}")

    # Create DataFrame from CoinTracking data
    cointracking_df = pd.DataFrame(cointracking_data, columns=columns)
    logging.info(f"Mapped {len(cointracking_df)} transactions to CoinTracking format.")
    return cointracking_df


def create_ct_row(transaction_type, buy_amount, buy_currency, sell_amount, sell_currency,
                 date_str, method_name, comment, tx_id, eth_tx_hash='', from_address='', to_address='',
                 fee_amount=None, fee_currency=None, exchange=''):
    """
    Create a single row for the CoinTracking DataFrame.

    Parameters:
        transaction_type (str): Type of the transaction.
        buy_amount (float): Amount bought.
        buy_currency (str): Currency bought.
        sell_amount (float): Amount sold.
        sell_currency (str): Currency sold.
        date_str (str): Date of the transaction.
        method_name (str): Method name.
        comment (str): Comment for the transaction.
        tx_id (str): Transaction ID.
        eth_tx_hash (str): Ethereum Transaction Hash.
        from_address (str): Sender address.
        to_address (str): Recipient address.
        fee_amount (float): Fee amount.
        fee_currency (str): Fee currency.
        exchange (str): Exchange address(es).

    Returns:
        dict: A dictionary representing a row in the CoinTracking DataFrame.
    """
    ct_row = {
        'Type': transaction_type,
        'Buy Amount': buy_amount,
        'Buy Cur.': buy_currency,
        'Sell Amount': sell_amount,
        'Sell Cur.': sell_currency,
        'Fee Amount': fee_amount if fee_amount not in [None, ''] else '',
        'Fee Cur.': fee_currency if fee_currency not in [None, ''] else '',
        'Wallet Address': exchange,  # Populate with exchange address
        'Trade Group': method_name,
        'Comment': comment,
        'Date': date_str,
        'Liquidity pool': '',
        'Tx-ID': tx_id,
        'Ethereum Tx Hash': eth_tx_hash,
        'Transfer From': from_address,
        'Transfer To': to_address
    }
    return ct_row


def classify_transaction(net_positive_tokens, net_negative_tokens):
    """
    Classify the transaction type based on net positive and negative tokens.

    Parameters:
        net_positive_tokens (list): List of tokens with net positive amounts.
        net_negative_tokens (list): List of tokens with net negative amounts.

    Returns:
        str: Classified transaction type.
    """
    num_net_positive = len(net_positive_tokens)
    num_net_negative = len(net_negative_tokens)

    if num_net_positive == 1 and num_net_negative >= 2:
        return 'Provide Liquidity'
    elif num_net_positive >= 2 and num_net_negative == 1:
        return 'Remove Liquidity'
    elif num_net_positive > 0 and num_net_negative > 0:
        return 'Trade'
    elif num_net_negative > 0:
        return 'Withdrawal'
    elif num_net_positive > 0:
        return 'Deposit'
    else:
        return 'Other Transaction'