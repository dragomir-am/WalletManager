import binascii
import hashlib
import os
import sqlite3
import sys
import time

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow
from PyQt5.uic import loadUi
from auxHelp.db_actions import Actions

from auxHelp.email_verification import email_syntax, send_email_otp
from auxHelp.models import User, WalletDetails, ExternalWallets
# from blockchain.infura import Infura
from wallet.wallet_generation import generate_wallet

path_dir: str = r"C:\Users\drago\PycharmProjects\WalletManager\AppGUI\\"
db = Actions()
user = User()
wd = WalletDetails()
ec = ExternalWallets()


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


class CreateWallet(QMainWindow):
    def __init__(self):
        super(CreateWallet, self).__init__()
        loadUi(path_dir + "wallet_manager_2.ui", self)
        self.language = ""
        self.coin = ""
        self.purpose = ""
        self.success = True
        self.tab_index = 0
        number_wallets = str(db.get_number_of_wallets())
        number_accounts = str(db.get_number_of_accounts())

        self.counter_wallets.setText("Active Wallets: " + str(number_wallets[1]))
        self.counter_accounts.setText("Active Accounts: " + str(number_accounts[1]))

        self.tabWidget.currentChanged.connect(self.tabChanged)

        self.passphrase_field.setEchoMode(QtWidgets.QLineEdit.Password)

        if self.language_comboBox.currentIndex() != -1:
            self.get_language()

        if self.coin_comboBox.currentIndex() != -1:
            self.get_coin()

        if self.purpose_comboBox.currentIndex() != -1:
            self.get_purpose()

        self.generate_button.clicked.connect(self.create_wallet)

        self.ec_insert_btn.clicked.connect(self.add_external_classic_wallet)

    def tabChanged(self):
        self.tab_index = self.tabWidget.currentIndex()
        if self.tab_index == 1:
            self.get_view_wallets_data()
        # elif self.tab_index == 3:

    def clear_input(self):
        self.passphrase_field.clear()
        self.language_comboBox.setCurrentIndex(-1)
        self.quantity_comboBox.setCurrentIndex(-1)
        self.coin_comboBox.setCurrentIndex(-1)
        self.purpose_comboBox.setCurrentIndex(-1)

    def next_tab(self):
        cur_position = self.tabWidget.currentIndex()
        if cur_position < len(self.tabWidget) - 1:
            self.tabWidget.setCurrentIndex(cur_position + 1)

    def get_options(self):
        self.language = wd.language[self.language_comboBox.currentIndex()]
        wd.quantity = int(self.quantity_comboBox.currentText())
        self.coin = wd.currency[self.coin_comboBox.currentIndex()]
        self.purpose = wd.change[self.purpose_comboBox.currentIndex()]

    def prev_tab(self):
        cur_position = self.tabWidget.currentIndex()
        if cur_position > 0:
            self.tabWidget.setCurrentIndex(cur_position - 1)

    def create_wallet(self):
        wd.passphrase = self.passphrase_field.text()
        self.get_options()
        try:
            generate_wallet(self.language, wd.passphrase, self.coin, wd.account, user.email)
        except:
            self.success = False

        if self.success:
            self.clear_input()
            self.next_tab()

    def get_view_wallets_data(self):
        data = db.get_wallet_derivation()
        self.tableWidget.setRowCount(0)
        row_index = 0
        for row in data:
            self.tableWidget.insertRow(row_index)
            self.tableWidget.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.tableWidget.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row[2]))
            self.tableWidget.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row[3]))
            self.tableWidget.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row[4]))
            row_index += 1

    def add_external_classic_wallet(self):
        db.create_external_classic_wallet()

        ec.currency = self.ec_coin_field.text()
        ec.public_key = self.ec_pubk_field.text()
        ec.private_key = self.ec_privk_field.text()

        db.insert_external_classic_wallet(ec.currency, ec.public_key, ec.private_key, "test@yahoo.com")

        data = db.get_external_classic_wallet()

        self.ec_tableWidget.setRowCount(0)
        row_index = 0
        for row in data:
            self.ec_tableWidget.insertRow(row_index)
            self.ec_tableWidget.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.ec_tableWidget.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row[1]))
            self.ec_tableWidget.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row[2]))
            row_index += 1







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
wallet = CreateWallet()  # open_create_wallet()
widget.addWidget(wallet)
# widget.addWidget(login)
widget.show()
# open_login()

try:
    sys.exit(app.exec_())
except:
    print("Exiting")
