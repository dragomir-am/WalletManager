import sqlite3

from auxHelp.secure_login import verify_password, hash_password


# from pysqlcipher3 import dbapi2 as sqlite3
# from models import User
#
# user = User()


class Actions:

    def __init__(self):
        path = r'C:/Users/drago/PycharmProjects/WalletManager/storage/storage.db'
        # self.key = f"PRAGMA KEY={user.password}"
        # self.conn = sqlite3.connect(path)
        # self.cur.execute(key)
        # self.conn.commit()
        self.conn = sqlite3.connect(path)
        self.cur = self.conn.cursor()
        self.conn.row_factory = sqlite3.Row

    def create_user_table(self):
        self.cur.execute("CREATE TABLE IF NOT EXISTS login_info (email TEXT, password TEXT)")
        self.conn.commit()

    def insert_user_table(self, email, password):
        hashed_password = hash_password(password)
        user_info = [email, hashed_password]
        self.cur.execute('INSERT INTO login_info (email, password) VALUES (?,?)', user_info)
        self.conn.commit()

    def delete_user_record(self):
        self.cur.execute('DELETE FROM login_info WHERE ROWID=(SELECT MAX(rowid) FROM login_info)')
        self.conn.commit()

    def update_user_record(self, email, new_password):
        updated_pass = hash_password(new_password)
        query = 'UPDATE login_info SET password = ? WHERE email = ?'
        self.cur.execute(query, (updated_pass, email))
        self.conn.commit()

    def find_user_account(self, email):
        self.cur.execute('SELECT email FROM login_info')
        results_user = {result_user[0] for result_user in self.cur.fetchall()}
        if email not in results_user:
            existing_account = False
        else:
            existing_account = True
        return existing_account

    def validate_user_login(self, email, password):
        query_pass = 'SELECT password FROM login_info WHERE email =\'' + email + "\'"
        self.cur.execute(query_pass)
        result_pass = self.cur.fetchone()[0]

        if verify_password(result_pass, password):
            pass_found = True
        else:
            pass_found = False

        return pass_found

    def create_wallet_table(self, wallet_keys):
        columns = ", ".join("{field} TEXT".format(field=field) for field in wallet_keys)

        self.cur.execute("""
                    CREATE TABLE IF NOT EXISTS wallet_core(
                    {columns}
                    )
                    """.format(columns=columns))
        self.conn.commit()

    def create_derivation_wallet(self):
        self.cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS wallet_derivation ( 
                    coin TEXT,
                    address_index TEXT,
                    path TEXT,
                    address TEXT,
                    private_key TEXT,
                    change TEXT,
                    account TEXT,
                    finger_print TEXT
                    )""")

        self.conn.commit()

    def create_external_classic_wallet(self):
        self.cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS external_classic_wallet (
                    currency TEXT,
                    public_key TEXT,
                    private_key TEXT,
                    email TEXT,
                    FOREIGN KEY(email) REFERENCES login_info(email)
                    )""")

        self.conn.commit()

    def create_external_hd_wallet(self):
        self.cur.execute(f"""
                   CREATE TABLE IF NOT EXISTS external_classic_wallet (
                   currency TEXT,
                   email TEXT,
                   mnemonic TEXT,
                   FOREIGN KEY(email) REFERENCES login_info(email)
                   )""")

        self.conn.commit()

    def insert_wallet_core(self, wallet_keys, wallet_values):
        query = ("INSERT INTO wallet_core ({fields}) VALUES ({marks})"
                 .format(fields=", ".join(wallet_keys),
                         marks=", ".join("?" * len(wallet_values))))

        self.cur.execute(query, wallet_values)
        self.conn.commit()

    def insert_wallet_derivation(self, coin, index, path, address, private_key, change, account, fingerprint):
        query = f"INSERT INTO wallet_derivation (coin, address_index, path, address, private_key, " \
                f"change, account, finger_print) VALUES (?,?,?,?,?,?,?,?) "
        self.cur.execute(query, (coin, index, path, address, private_key, change, account, fingerprint))
        self.conn.commit()

    def insert_external_classic_wallet(self, coin, public_key, private_key):
        query = f"INSERT INTO external_classic_wallet (coin, public_key, private_key) VALUES (?,?,?) "
        self.cur.execute(query, (coin, public_key, private_key))
        self.conn.commit()

    def insert_external_hd_wallet(self, coin, mnemonic, email):
        query = f"INSERT INTO wallet_derivation (coin, mnemonic) VALUES (?,?,?) "
        self.cur.execute(query, (coin, mnemonic, email))
        self.conn.commit()

    def get_wallet_derivation(self):
        query = "SELECT * FROM wallet_derivation"
        self.cur.execute(query)
        self.conn.commit()
        rows = self.cur.fetchall()

        return rows

    def get_wallet_core(self, fingerprint):
        query = f"SELECT mnemonic, language, passphrase FROM wallet_core WHERE finger_print='{fingerprint}' "
        self.cur.execute(query)
        row = self.cur.fetchone()
        rowDict = dict(zip([c[0] for c in self.cur.description], row))

        return rowDict

    def get_derivation_account(self, path):
        self.cur.execute("SELECT account, address_index, change FROM wallet_derivation WHERE path =? ", (path,))
        details = self.cur.fetchall()
        return details

    def get_number_of_accounts(self):
        self.cur.execute("SELECT COUNT (DISTINCT(account)) FROM wallet_derivation")
        result = self.cur.fetchone()
        return result

    def get_number_of_wallets(self):
        self.cur.execute('SELECT COUNT(*) FROM wallet_core')
        result = self.cur.fetchone()
        return result

    def check_derivation_address(self, path):
        self.cur.execute("SELECT path FROM wallet_derivation WHERE path=?", (path,))
        result = self.cur.fetchone()
        print(result)
        if result is not None:
            return True
        else:
            return False

    def get_last_index(self, account):
        f_account = str(account) + "'"
        # self.cur.execute("SELECT address_index FROM wallet_derivation WHERE rowID=(SELECT MAX(rowID) AND account =? "
        #                  "FROM wallet_derivation)", (f_account,))
        self.cur.execute("SELECT MAX(address_index) FROM wallet_derivation WHERE account=?",
                         (f_account,))

        result = self.cur.fetchone()
        print(result)
        if result[0] is not None:
            return result[0]
        else:
            return -1


db = Actions()
a = db.get_last_index(4)
#
# a = db.get_number_of_accounts()
# w = db.get_number_of_wallets()
print("A: " + str(a))
