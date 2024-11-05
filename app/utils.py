# utils.py

import bech32

def sanitize(value):
    if isinstance(value, str):
        return value.replace('\x00', '').replace('\u0000', '')
    return value

def rename_address(address, address_name_map):
    return address_name_map.get(address, address)

def bech32_to_hex(bech32_address):
    hrp, data = bech32.bech32_decode(bech32_address)
    if data is None:
        raise ValueError(f"Invalid Bech32 address: {bech32_address}")
    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None:
        raise ValueError(f"Invalid Bech32 address: {bech32_address}")
    hex_address = '0x' + ''.join('{:02x}'.format(b) for b in decoded)
    return hex_address.lower()

def hex_to_bech32(hex_address, hrp='evmos'):
    """
    Convert a hex address to bech32 format.

    Parameters:
        hex_address (str): Hexadecimal address, with or without '0x' prefix.
        hrp (str): Human-readable part for Bech32 encoding. Default is 'evmos'.

    Returns:
        str: Bech32 encoded address.

    Raises:
        ValueError: If the hex_address is invalid.
    """
    if hex_address.startswith('0x') or hex_address.startswith('0X'):
        hex_address = hex_address[2:]
    if len(hex_address) != 40:
        raise ValueError(f"Invalid hex address length: {hex_address}")
    try:
        data = bytes.fromhex(hex_address)
    except ValueError:
        raise ValueError(f"Invalid hex address: {hex_address}")
    converted = bech32.convertbits(data, 8, 5)
    if converted is None:
        raise ValueError(f"Error converting hex to bech32: {hex_address}")
    bech32_address = bech32.bech32_encode(hrp, converted)
    return bech32_address.lower()