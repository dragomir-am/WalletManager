import sys

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
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
    otp_window.setFixedWidth(603)
    otp_window.setFixedHeight(397)
    user.otp = send_email_otp(email)
    otp_window.exec()


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
    widget.setFixedWidth(588)
    widget.setFixedHeight(488)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_view_addresses():
    view_addresses = ViewAddresses()
    widget.addWidget(view_addresses)
    widget.setFixedWidth(970)
    widget.setFixedHeight(510)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_add_external():
    add_external = AddExternalWallets()
    widget.addWidget(add_external)
    widget.setFixedWidth(935)
    widget.setFixedHeight(616)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def open_generate_addresses():
    gen_add = GenerateAddresses()
    widget.addWidget(gen_add)
    widget.setFixedWidth(588)
    widget.setFixedHeight(488)
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

        self.view_wallets_btn.clicked.connect(open_view_addresses)

        self.add_ext_wallet_btn.clicked.connect(open_add_external)


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


class CreateWallet(QDialog):
    def __init__(self):
        super(CreateWallet, self).__init__()
        loadUi(path_dir + "create_wallet.ui", self)
        self.language = ""
        self.coin = ""
        self.change = ""
        number_wallets = str(db.get_number_of_wallets())

        self.counter_wallets.setText("Active Wallets: " + str(number_wallets[1]))

        self.generate_button.clicked.connect(self.create_wallet)

        self.back_btn.clicked.connect(open_wallet_manager)

    def get_options(self):
        self.language = wd.language[self.language_comboBox.currentIndex()]
        self.coin = wd.currency_class[self.coin_comboBox.currentIndex()]

    def clear_input(self):
        self.language_comboBox.setCurrentIndex(-1)
        self.coin_comboBox.setCurrentIndex(-1)
        self.passphrase_field.clear()
        self.name_field.clear()

    def create_wallet(self):
        wd.passphrase = self.passphrase_field.text()
        wd.wallet_name = self.name_field.text()

        self.get_options()

        try:
            generate_wallet(self.language, wd.passphrase, self.coin, wd.account, user.email)
            wd.wallet_generated = "Wallet generated, derive new address now!"
            self.clear_input()
            open_view_addresses()
        except:
            wd.wallet_generated = "Wallet generation failed, try again!"


class AddExternalWallets(QDialog):
    def __init__(self):
        super(AddExternalWallets, self).__init__()
        loadUi(path_dir + "add_external_wallets.ui", self)
        self.coin = ""
        self.language = ""

        self.ec_back_btn.clicked.connect(open_wallet_manager)

        self.ehd_back_btn.clicked.connect(open_wallet_manager)

        self.ehd_add_btn.clicked.connect(self.add_external_hd_wallet)

        self.ec.add_btn.clicked.connect(self.add_external_classic_wallet)

    def add_external_classic_wallet(self):
        db.create_external_classic_wallet()

        ec.currency = self.ec_coin_field.text()
        ec.public_key = self.ec_pubk_field.text()
        ec.private_key = self.ec_privk_field.text()

        db.insert_external_classic_wallet(ec.currency, ec.public_key, ec.private_key, "test@yahoo.com", "wallet1")

        data = db.get_external_classic_wallet()

        self.ec_tableWidget.setRowCount(0)
        row_index = 0
        for row in data:
            self.ec_tableWidget.insertRow(row_index)
            self.ec_tableWidget.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.ec_tableWidget.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row[1]))
            self.ec_tableWidget.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row[2]))
            self.ec_tableWidget.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row[3]))
            row_index += 1

    def add_external_hd_wallet(self):
        db.create_external_hd_wallet()

        wd.passphrase = self.ehd_passphrase_field.text()
        self.language = wd.language[self.ehd_language_comboBox.currentIndex()]
        self.coin = self.ehd_currency_comboBox.currentText()
        wd.mnemonic = self.ehd_mnemonic_field.text()

        db.insert_external_hd_wallet(self.coin, wd.mnemonic, self.language, wd.passphrase, "test@yahoo.com")

        data = db.get_external_hd_wallet()

        self.ehd_tableWidget.setRowCount(0)
        row_index = 0
        for row in data:
            self.ehd_tableWidget.insertRow(row_index)
            self.ehd_tableWidget.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.ehd_tableWidget.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row[1]))
            self.ehd_tableWidget.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row[2]))
            self.ehd_tableWidget.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row[3]))
            self.ehd_tableWidget.setItem(row_index, 4, QtWidgets.QTableWidgetItem(row[4]))
            row_index += 1


class ViewAddresses(QDialog):
    def __init__(self):
        super(ViewAddresses, self).__init__()
        loadUi(path_dir + "view_addresses.ui", self)

        self.back_btn.clicked.connect(open_wallet_manager)

        self.add_btn.clicked.connect(open_generate_addresses)

        self.get_view_wallets_data()

    def get_view_wallets_data(self):
        data = db.get_wallet_derivation()
        self.vw_tableWidget.setRowCount(0)
        row_index = 0
        for row in data:
            self.vw_tableWidget.insertRow(row_index)
            self.vw_tableWidget.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.vw_tableWidget.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row[2]))
            self.vw_tableWidget.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row[3]))
            self.vw_tableWidget.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row[4]))
            self.vw_tableWidget.setItem(row_index, 4, QtWidgets.QTableWidgetItem(row[5]))
            self.vw_tableWidget.setItem(row_index, 5, QtWidgets.QTableWidgetItem(row[6]))
            self.vw_tableWidget.setItem(row_index, 6, QtWidgets.QTableWidgetItem(row[8]))
            row_index += 1


class GenerateAddresses(QDialog):
    def __init__(self):
        super(GenerateAddresses, self).__init__()
        loadUi(path_dir + "add_address.ui", self)

        number_acc = str(db.get_number_of_accounts())

        self.counter_accounts.setText("Active Accounts: " + str(number_acc[1]))


class ViewDetails(QDialog):
    def __init__(self):
        super(ViewDetails, self).__init__()
        loadUi(path_dir + "view_details.ui", self)


app = QApplication(sys.argv)
login = Login()
widget = QtWidgets.QStackedWidget()
cr = CreateWallet()
mr = WalletManager()
# wallet = CreateWallet()  # open_create_wallet()
# widget.addWidget(wallet)
# widget.addWidget(login)
widget.show()
open_wallet_manager()
# open_login()
# open_create_wallet()

try:
    sys.exit(app.exec_())
except:
    print("Exiting")
