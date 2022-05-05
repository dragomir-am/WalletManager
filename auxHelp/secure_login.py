import binascii
import hashlib
import base64
import random
import time

import pyqrcode
import os


def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(1024)).hexdigest().encode('ascii')
    passwordhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                       salt, 100000)
    passwordhash = binascii.hexlify(passwordhash)
    return (salt + passwordhash).decode('ascii')


def verify_password(stored_password, inserted_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    passwordhash = hashlib.pbkdf2_hmac('sha512',
                                       inserted_password.encode('utf-8'),
                                       salt.encode('ascii'),
                                       100000)
    passwordhash = binascii.hexlify(passwordhash).decode('ascii')
    return passwordhash == stored_password


# Generate QR code

def generate_qr_image(password):
    pin = random.randint(100000, 999999)

    to_encode = password + str(pin)

    to_encode_bytes = to_encode.encode('utf-8')
    base64_bytes = base64.b64encode(to_encode_bytes)
    base64_value = base64_bytes.decode('utf-8')

    hexed_value = base64_value.encode('utf-8').hex()

    # Generate QR code and embed string
    url = pyqrcode.create(hexed_value)

    # Create and save the svg file naming "myqr.svg"
    url.svg("C:/Users/drago/PycharmProjects/WalletManager/auxHelp/myqr.svg", scale=8)

    return pin
