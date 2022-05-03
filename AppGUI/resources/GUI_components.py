class CreateWallet(QMainWindow):
    def __init__(self):
        super(CreateWallet, self).__init__()
        loadUi(path_dir + "wallet_manager_2.ui", self)
        self.language = ""
        self.coin = ""
        self.change = ""
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

        self.ehd_insert_btn.clicked.connect(self.add_external_hd_wallet)

    def tabChanged(self):
        self.tab_index = self.tabWidget.currentIndex()
        if self.tab_index == 1:
            self.get_view_wallets_data()
        # elif self.tab_index == 3:

    def clear_input_tab_create_wallet(self):
        self.passphrase_field.clear()
        self.language_comboBox.setCurrentIndex(-1)
        self.coin_comboBox.setCurrentIndex(-1)

    def next_tab(self):
        cur_position = self.tabWidget.currentIndex()
        if cur_position < len(self.tabWidget) - 1:
            self.tabWidget.setCurrentIndex(cur_position + 1)


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
            self.clear_input_tab_create_wallet()
            self.next_tab()

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
            # Instead of fingerprint, display wallet name = row[8]
            self.vw_tableWidget.setItem(row_index, 6, QtWidgets.QTableWidgetItem(row[7]))
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
            row_index += 1

    def update_account_wallet_status(self):
        pass
