# app/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session, current_app
import os
from .main import process_wallets
import pandas as pd
from io import BytesIO
from urllib.parse import urlparse
import uuid
import logging
import shutil

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        wallet_input = request.form.get('wallet_addresses')
        max_tx = request.form.get('max_transactions')
        custom_api = request.form.get('custom_api')  # Capture custom API

        if not wallet_input:
            flash('Please enter at least one wallet address.', 'danger')
            return redirect(url_for('main.index'))

        # Process wallet addresses
        if ',' in wallet_input:
            input_addresses = [addr.strip() for addr in wallet_input.split(',')]
        else:
            input_addresses = [addr.strip() for addr in wallet_input.split()]

        if max_tx:
            try:
                max_transactions = int(max_tx)
                if max_transactions <= 0:
                    flash('Maximum transactions must be a positive integer.', 'danger')
                    return redirect(url_for('main.index'))
            except ValueError:
                flash('Invalid input for maximum transactions.', 'danger')
                return redirect(url_for('main.index'))
        else:
            max_transactions = None

        # Capture the custom API address if provided
        if custom_api:
            api_base_url = custom_api.strip()
            # Validate the URL
            parsed_url = urlparse(api_base_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                flash('Invalid API address provided. Please enter a valid URL.', 'danger')
                return redirect(url_for('main.index'))
        else:
            api_base_url = None  # Use default API in backend

        # Generate a unique request ID
        request_id = str(uuid.uuid4())
        logging.info(f"Generated request ID: {request_id}")

        try:
            # Process wallets and fetch transactions
            results = process_wallets(input_addresses, max_transactions, api_base_url, request_id=request_id)

            # Get the CoinTracking DataFrame
            cointracking_df = results.get('cointracking_df', pd.DataFrame())
            if not cointracking_df.empty:
                try:
                    # Convert 'Date' column to datetime
                    cointracking_df['Date'] = pd.to_datetime(cointracking_df['Date'], format='%d-%m-%Y %H:%M:%S')
                except Exception as e:
                    flash(f"Error converting 'Date' column to datetime: {e}", 'danger')
                    logging.error(f"Date conversion error: {e}")
                    return redirect(url_for('main.index'))

                # Sort by 'Date' ascending
                cointracking_df.sort_values('Date', inplace=True)

                # Reset index after sorting
                cointracking_df.reset_index(drop=True, inplace=True)

                # Define output filename based on wallet addresses
                if len(input_addresses) == 1:
                    address = input_addresses[0]
                    # Sanitize the address for use in a filename
                    sanitized_address = address.replace(' ', '').replace('/', '_').replace('\\', '_')
                    output_filename = f'{sanitized_address}_{request_id}.xlsx'
                else:
                    # Join multiple addresses with underscores, limit total length if necessary
                    sanitized_addresses = '_'.join([addr.replace(' ', '').replace('/', '_').replace('\\', '_') for addr in input_addresses])
                    # Optionally, limit the length to prevent filesystem issues
                    sanitized_addresses = sanitized_addresses[:50]  # Adjust as needed
                    output_filename = f'{sanitized_addresses}_{request_id}.xlsx'

                logging.info(f"Output Excel file will be named: {output_filename}")

                # Save to Excel in the temp directory
                temp_dir = current_app.config.get('TEMP_DIR', 'temp')  # Ensure TEMP_DIR is defined in config
                os.makedirs(temp_dir, exist_ok=True)
                file_path = os.path.join(temp_dir, output_filename)

                # Save the DataFrame to the Excel file
                cointracking_df.to_excel(file_path, index=False, engine='openpyxl')
                logging.info(f"Excel file saved to: {file_path}")

                # Store the filename and desired download name in the session
                session['excel_file'] = output_filename
                session['download_filename'] = output_filename  # Use the dynamic filename

                cointracking_available = True
            else:
                cointracking_available = False
                flash('No transactions found for the provided wallet address(es).', 'info')

            return render_template('results.html',
                                   cointracking_available=cointracking_available)
        except Exception as e:
            flash(f'An error occurred while processing: {e}', 'danger')
            logging.error(f"An error occurred while processing: {e}")
            return redirect(url_for('main.index'))
        finally:
            # Clean up temporary fetched_transactions directory
            unique_output_dir = os.path.join('fetched_transactions', f"request_{request_id}")
            if os.path.exists(unique_output_dir):
                try:
                    shutil.rmtree(unique_output_dir)
                    logging.info(f"Cleaned up temporary directory: {unique_output_dir}")
                except Exception as e:
                    logging.error(f"Error cleaning up temporary directory {unique_output_dir}: {e}")
            else:
                logging.warning(f"Temporary directory {unique_output_dir} does not exist. Nothing to clean up.")

    return render_template('index.html')

@main.route('/download_transactions_excel')
def download_transactions_excel():
    unique_filename = session.get('excel_file', None)
    download_filename = session.get('download_filename', 'transactions.xlsx')
    if unique_filename:
        temp_dir = current_app.config.get('TEMP_DIR', 'temp')  # Ensure TEMP_DIR is defined in config
        file_path = os.path.join(temp_dir, unique_filename)
        if os.path.exists(file_path):
            try:
                return send_file(
                    file_path,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True,
                    download_name=download_filename  # Use the dynamic filename
                )
            except Exception as e:
                flash(f"Error sending file: {e}", 'danger')
                logging.error(f"Error sending file {file_path}: {e}")
                return redirect(url_for('main.index'))
        else:
            flash('The requested file does not exist.', 'danger')
            logging.error(f"File {file_path} does not exist.")
            return redirect(url_for('main.index'))
    else:
        flash('No transaction data available for download.', 'warning')
        return redirect(url_for('main.index'))