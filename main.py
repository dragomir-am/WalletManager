import binascii
import hashlib
import os
import sqlite3
import sys
import time

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi
from auxHelp.db_actions import Actions

from auxHelp.email_verification import email_syntax, send_email_otp
from auxHelp.user_model import User
from blockchain.infura import Infura

path_dir: str = r"C:\Users\drago\PycharmProjects\WalletManager\AppGUI\\"
db = Actions()
user = User()


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
    # widget.addWidget(otp_window)
    # widget.setFixedWidth(603)
    # widget.setFixedHeight(397)
    otp_window.setFixedWidth(603)
    otp_window.setFixedHeight(397)
    user.otp = send_email_otp(email)
    otp_window.exec()
    # widget.setCurrentIndex(widget.currentIndex() + 1)


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
        user.email = self.email_field.text()
        user.password = self.pass_field.text()
        if len(user.email) == 0 or len(user.password) == 0:
            self.empty_error.setText("Please enter both username and password")
            self.acc_error.setText("")
            self.pass_error.setText("")
        elif db.find_user_account(user.email) is not True:
            self.acc_error.setText("Account does not exist!")
            self.empty_error.setText("")
            self.pass_error.setText("")
        elif db.validate_user_login(user.email, user.password) is not True:
            self.pass_error.setText("Incorrect password")
            self.empty_error.setText("")
            self.empty_error.setText("")
        else:
            self.title_label.setText("Login Successful")
            open_wallet_manager()

    def update_message(self, message):
        self.title_label.setText(message)


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

        db.create_user_table()

    def register_function(self):
        user.email = self.register_email_field.text()
        user.password = self.register_pass_field.text()
        confirm_password = self.register_confirm_pass_field.text()

        if len(user.password) == 0 or len(confirm_password) == 0 or len(user.email) == 0:
            self.register_empty_error.setText("Please input all fields!")
            self.register_acc_error.setText("")
            self.register_pass_error.setText("")
            self.register_invalid_email_error.setText("")
        elif email_syntax(user.email) is not True:
            self.register_acc_error.setText("")
            self.register_pass_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("Email address is invalid!")
        elif db.find_user_account(user.email) is True:
            self.register_acc_error.setText("Email address already belongs to an account!")
            self.register_pass_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("")
        elif user.password != confirm_password:
            self.register_pass_error.setText("Passwords do not match!")
            self.register_acc_error.setText("")
            self.register_empty_error.setText("")
            self.register_invalid_email_error.setText("")
        else:
            db.insert_user_table(user.email, user.password)
            open_otp(user.email)


class OTP_window(QDialog):

    def __init__(self):
        super(OTP_window, self).__init__()
        loadUi(path_dir + "otp.ui", self)
        self.resend_btn.clicked.connect(self.resend_otp)
        self.validate_btn.clicked.connect(self.validate_otp)
        self.otp_inserted = self.otp_field.text()
        self.count = 0

    def resend_otp(self):
        user.otp = send_email_otp(user.email)
        self.timer_info_label.setText("We have resent the confirmation code")

    def validate_otp(self):
        self.otp_inserted = self.otp_field.text()
        self.timer_info_label.setText("")

        if user.otp == self.otp_inserted:
            open_login()
            self.timer_info_label.setText("Registration complete, you may close the window now!")

        else:
            self.timer_info_label.setText("Invalid code: You have " + str(3 - self.count) + " attempts left")
            self.count = self.count + 1

        if self.count > 3:
            self.timer_info_label.setText("Too many attempts, go back to Register!")
            db.delete_user_record()
            open_register()


class ChangePassword(QDialog):
    def __init__(self):
        super(ChangePassword, self).__init__()
        loadUi(path_dir + "update_password.ui", self)
        user.email = self.email_field.text()
        self.new_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.check_pass_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.validate_btn.clicked.connect(self.update_password)
        self.send_btn.clicked.connect(send_email_otp(user.email))

    def compare_otp(self):
        code = self.otp_field.text()
        otp_generated = user.otp

        if otp_generated != code:
            otp_integrity = False

        else:
            otp_integrity = True

        return otp_integrity

    def update_password(self):
        code = self.otp_field.text()
        user.email = self.email_field.text()
        new_password = self.new_pass_field.text()
        check_password = self.check_pass_field.text()

        if len(user.email) == 0 or len(new_password) == 0 or len(check_password) == 0 or len(code) == 0:
            self.empty_error.setText("Please input all fields!")
            self.pass_error.setText("")
            self.acc_error.setText("")
            self.mfa_error.setText("")
        elif db.find_user_account(user.email) is not True:
            self.empty_error.setText("")
            self.pass_error.setText("")
            self.acc_error.setText("Email address does not exist")
            self.mfa_error.setText("")
        elif email_syntax(user.email) is not True:
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
            db.update_user_record(user.email, new_password)

            login = Login()
            widget.addWidget(login)
            widget.setFixedWidth(1011)
            widget.setFixedHeight(621)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            login.update_message(message="Password updated, you can login now!")


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
