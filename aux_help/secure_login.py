import binascii
import hashlib
import os
import sqlite3
import getpass

import rsa

# generate public and private keys with
# rsa.newkeys method,this method accepts
# key length as its parameter
# key length should be atleast 16
publicKey, privateKey = rsa.newkeys(515)

# this is the string that we will be encrypting


# rsa.encrypt method is used to encrypt
# string with public key string should be
# encode to byte string before encryption
# with encode method

# the encrypted message can be decrypted
# with ras.decrypt method and private key
# decrypt method returns encoded byte string,
# use decode method to convert it to string
# public key cannot be used for decryption

print("Public ", publicKey)
print("Private ", privateKey)
user = input("Enter your email address: ")
password = input("Enter a password: ")

encrypted_password = rsa.encrypt(password.encode(), publicKey)

print("Encrypted:", encrypted_password)

decrypted = rsa.decrypt(encrypted_password, privateKey).decode()
print("Decrypted: ", decrypted)
