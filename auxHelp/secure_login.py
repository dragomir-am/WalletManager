import binascii
import hashlib
import os


def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(1024)).hexdigest().encode('ascii')
    passwordhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                       salt, 100000)
    passwordhash = binascii.hexlify(passwordhash)
    return (salt + passwordhash).decode('ascii')


# Check hashed password validity
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
