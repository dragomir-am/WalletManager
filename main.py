import binascii
import hashlib
import os
import sqlite3
import sys
import time

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi

from aux_help.email_verification import email_syntax, send_email_otp
from blockchain.infura import Infura


path_dir: str = r"C:\Users\drago\PycharmProjects\WalletManager\AppGUI\\"


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


def account_exists(email):
    conn = sqlite3.connect("storage.db")
    cur = conn.cursor()
    cur.execute('SELECT email FROM login_info')
    results_user = {result_user[0] for result_user in cur.fetchall()}
    if email not in results_user:
        existing_account = False
    else:
        existing_account = True
    return existing_account


def validate_login(email, password):
    conn = sqlite3.connect("storage.db")
    cur = conn.cursor()

    query_pass = 'SELECT password FROM login_info WHERE email =\'' + email + "\'"
    cur.execute(query_pass)
    result_pass = cur.fetchone()[0]

    if verify_password(result_pass, password):
        pass_found = True
    else:
        pass_found = False

    return pass_found


def get_email(email):
    return email


def open_register():
    register = Register()
    widget.addWidget(register)
    widget.setFixedWidth(609)
    widget.setFixedHeight(738)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_login():
    login = Login()
    widget.addWidget(login)
    widget.setFixedWidth(1011)
    widget.setFixedHeight(621)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_otp(email):
    otp_window = OTP_window()
    widget.addWidget(otp_window)
    widget.setFixedWidth(603)
    widget.setFixedHeight(397)
    widget.setCurrentIndex(widget.currentIndex() + 1)
    process_otp(email)


def open_change_password():
    update = ChangePassword()
    widget.addWidget(update)
    widget.setFixedWidth(1011)
    widget.setFixedHeight(621)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_wallet_manager():
    wallet_manager = WalletManager()
    widget.addWidget(wallet_manager)
    widget.setFixedWidth(510)
    widget.setFixedHeight(699)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_create_wallet():
    create_wallet = CreateWallet()
    widget.addWidget(create_wallet)
    widget.setFixedWidth(791)
    widget.setFixedHeight(511)
    widget.setCurrentIndex(widget.currentIndex() + 1)


class Login(QDialog):
    def __init__(self):
        super(Login, self).__init__()
        loadUi(path_dir + "login.ui", self)
        self.pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_login_btn.clicked.connect(self.login_function)
        self.login_noacc_btn.clicked.connect(open_register)
        self.login_forgot_btn.clicked.connect(open_change_password)

    # Adjust logic for message display
    def login_function(self):
        email = self.email_field.text()
        password = self.pass_field.text()
        if len(email) == 0 or len(password) == 0:
            self.empty_error.setText("Please enter both username and password")
            self.acc_error.setText("")
            self.pass_error.setText("")
        elif account_exists(email) is not True:
            self.acc_error.setText("Account does not exist!")
            self.empty_error.setText("")
            self.pass_error.setText("")
        elif validate_login(email, password) is not True:
            self.pass_error.setText("Incorrect password")
            self.empty_error.setText("")
            self.empty_error.setText("")
        else:
            self.title_label.setText("Login Successful")
            open_wallet_manager()

    def update_message(self):
        self.title_label.setText("Password updated, you can login now!")


class WalletManager(QDialog):
    def __init__(self):
        super(WalletManager, self).__init__()
        loadUi(path_dir + "wallet_manager.ui", self)
        self.create_wallet_btn.clicked.connect(open_create_wallet)


def generate_wallet(coin, wordlist_language, passphrase):
    pass



class CreateWallet(QDialog):
    def __init__(self):
        super(CreateWallet, self).__init__()
        loadUi(path_dir + "create_wallet.ui", self)

        self.generate_btn.clicked.connect(self.on_click)

    def on_click(self):
        wordlist_language = self.wordlist_combo.currentText()
        passphrase = self.passphrase_field.text()
        coin = self.coin_combo.currentText()
        # if coin == "Ethereum":
        #     eth.generate_eth_wallet(wordlist_language.lower(), passphrase)
        # elif coin == "Litecoin":
        #     ltc.generate_ltc_wallet(wordlist_language.lower(), passphrase)
        # elif coin == "Bitcoin":
        #     btc.generate_btc_wallet(wordlist_language.lower(), passphrase)
        # elif coin == "Dogecoin":
        #     doge.generate_doge_wallet(wordlist_language.lower(), passphrase)


class Register(QDialog):
    def __init__(self):
        super(Register, self).__init__()
        loadUi(path_dir + "register.ui", self)
        self.register_gotologin_btn.clicked.connect(open_login)
        self.register_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.register_confirm_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.register_register_btn.clicked.connect(self.register_function)

        conn = sqlite3.connect("storage.db")
        cur = conn.cursor()

        cur.execute("CREATE TABLE IF NOT EXISTS login_info (email TEXT, password TEXT)")
        conn.commit()

    def register_function(self):
        email = self.register_email_field.text()
        password = self.register_pass_field.text()
        confirm_password = self.register_confirm_pass_field.text()
        conn = sqlite3.connect("storage.db")
        cur = conn.cursor()

        if len(password) == 0 or len(confirm_password) == 0 or len(email) == 0:
            self.register_empty_error.setText("Please input all fields!")
            self.register_acc_error.setText("")
            self.register_pass_error.setText("")
            self.register_invalid_email_error.setText("")
        elif email_syntax(email) is not True:
            self.register_acc_error.setText("")
            self.register_pass_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("Email address is invalid!")
        elif account_exists(email) is True:
            self.register_acc_error.setText("Email address already belongs to an account!")
            self.register_pass_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("")
        elif password != confirm_password:
            self.register_pass_error.setText("Passwords do not match!")
            self.register_acc_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("")
        else:
            hashed_password = hash_password(password)
            user_info = [email, hashed_password]
            cur.execute('INSERT INTO login_info (email, password) VALUES (?,?)', user_info)
            conn.commit()
            conn.close()
            open_otp(email)


def process_otp(email):
    otp = send_email_otp(email)
    file = open("otp.txt", "w")
    file.write(otp)
    file.close()
    file = open("email.txt", "w")
    file.write(email)
    file.close()


class OTP_window(QDialog):

    def __init__(self):
        super(OTP_window, self).__init__()
        loadUi(path_dir + "otp.ui", self)
        self.resend_btn.clicked.connect(self.resend_otp)
        self.validate_btn.clicked.connect(self.validate_otp)
        self.otp_inserted = self.otp_field.text()
        self.count = 0

    def resend_otp(self):
        with open("email.txt", "r") as f:
            file = f.readlines()
            user_email = file[0]
        process_otp(user_email)
        self.timer_info_label.setText("We have resent the confirmation code")
        time.sleep(1)
        self.timer_info_label.setText("")

    def validate_otp(self):
        self.otp_inserted = self.otp_field.text()

        with open("otp.txt", "r") as f:
            file = f.readlines()
            otp_generated = file[0]

        if otp_generated == self.otp_inserted:
            self.timer_info_label.setText("Registration complete! You are being sent to login")
            time.sleep(5)
            open_login()
            os.remove("otp.txt")
            os.remove("email.txt")
        else:
            self.timer_info_label.setText("Invalid code")
            self.count = self.count + 1
            print(self.count)

        if self.count > 3:
            self.timer_info_label.setText("Too many attempts, go back to Register!")
            conn = sqlite3.connect("storage.db")
            cur = conn.cursor()
            cur.execute('DELETE FROM login_info WHERE ROWID=(SELECT MAX(rowid) FROM login_info)')
            conn.commit()
            conn.close()
            os.remove("otp.txt")
            os.remove("email.txt")
            open_register()


class ChangePassword(QDialog):
    def __init__(self):
        super(ChangePassword, self).__init__()
        loadUi(path_dir + "update_password.ui", self)
        self.new_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.check_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.validate_btn.clicked.connect(self.update_password)
        self.send_btn.clicked.connect(self.send)

    def send(self):
        email = self.email_field.text()
        process_otp(email)

    def compare_otp(self):
        code = self.otp_field.text()
        with open("otp.txt", "r") as f:
            file = f.readlines()
            otp_generated = file[0]

        if otp_generated != code:
            otp_integrity = False

        else:
            otp_integrity = True

        return otp_integrity

    def update_password(self):
        code = self.otp_field.text()
        email = self.email_field.text()
        new_password = self.new_pass_field.text()
        check_password = self.check_pass_field.text()

        if len(email) == 0 or len(new_password) == 0 or len(check_password) == 0 or len(code) == 0:
            self.empty_error.setText("Please input all fields!")
            self.pass_error.setText("")
            self.acc_error.setText("")
            self.mfa_error.setText("")
        elif account_exists(email) is not True:
            self.empty_error.setText("")
            self.pass_error.setText("")
            self.acc_error.setText("Email address does not exist")
            self.mfa_error.setText("")
        elif email_syntax(email) is not True:
            self.empty_error.setText("")
            self.pass_error.setText("")
            self.acc_error.setText("")
            self.mfa_error.setText("")
            self.invalid_email_address_error.setText("Invalid email address")
        elif new_password != check_password:
            self.empty_error.setText("")
            self.pass_error.setText("The passwords do not match!")
            self.acc_error.setText("")
            self.mfa_error.setText("")
        elif self.compare_otp() is not True:
            self.empty_error.setText("")
            self.pass_error.setText("")
            self.acc_error.setText("")
            self.mfa_error.setText("The OTP does not match!")
        else:
            updated_pass = hash_password(new_password)
            conn = sqlite3.connect("storage.db")
            cur = conn.cursor()
            query = 'UPDATE login_info SET password = ? WHERE email = ?'
            cur.execute(query, (updated_pass, email))
            conn.commit()
            conn.close()

            login = Login()
            widget.addWidget(login)
            widget.setFixedWidth(1011)
            widget.setFixedHeight(621)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            login.update_message()


app = QApplication(sys.argv)
# login = Login()
widget = QtWidgets.QStackedWidget()
# widget.addWidget(login)
widget.show()
open_login()

try:
    sys.exit(app.exec_())
except:
    print("Exiting")
