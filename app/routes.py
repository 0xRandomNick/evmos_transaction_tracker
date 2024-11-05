# app/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session, current_app
import os
from .main import process_wallets
import pandas as pd
from io import BytesIO
from urllib.parse import urlparse
import uuid

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

        try:
            results = process_wallets(input_addresses, max_transactions, api_base_url)

            # Convert CoinTracking DataFrame to Excel in memory with sorting
            cointracking_df = results['cointracking_df']
            if not cointracking_df.empty:
                try:
                    # Convert 'Date' column to datetime
                    cointracking_df['Date'] = pd.to_datetime(cointracking_df['Date'], format='%d-%m-%Y %H:%M:%S')
                except Exception as e:
                    flash(f"Error converting 'Date' column to datetime: {e}", 'danger')
                    return redirect(url_for('main.index'))

                # Sort by 'Date' ascending
                cointracking_df.sort_values('Date', inplace=True)

                # Reset index after sorting
                cointracking_df.reset_index(drop=True, inplace=True)

                # Generate a unique filename
                unique_filename = f"{uuid.uuid4()}.xlsx"
                temp_dir = current_app.config['TEMP_DIR']
                file_path = os.path.join(temp_dir, unique_filename)

                # Save to Excel
                cointracking_df.to_excel(file_path, index=False, engine='openpyxl')

                # Store the filename in the user's session
                session['excel_file'] = unique_filename

                cointracking_available = True
            else:
                cointracking_available = False

            return render_template('results.html',
                                   cointracking_available=cointracking_available)
        except Exception as e:
            flash(f'An error occurred while processing: {e}', 'danger')
            return redirect(url_for('main.index'))

    return render_template('index.html')

@main.route('/download_transactions_excel')
def download_transactions_excel():
    unique_filename = session.get('excel_file', None)
    if unique_filename:
        temp_dir = current_app.config['TEMP_DIR']
        file_path = os.path.join(temp_dir, unique_filename)
        if os.path.exists(file_path):
            return send_file(
                file_path,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name='transactions.xlsx'  # Updated parameter for Flask 2.x
            )
        else:
            flash('The requested file does not exist.', 'danger')
            return redirect(url_for('main.index'))
    else:
        flash('No transaction data available for download.', 'warning')
        return redirect(url_for('main.index'))
