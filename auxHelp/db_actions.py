import sqlite3
from auxHelp.secure_login import verify_password, hash_password


class Actions:

    def __init__(self):
        path = r'C:/Users/drago/PycharmProjects/WalletManager/storage/storage.db'
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()

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
            {columns},
            PRIMARY KEY(finger_print, email)
            )
            """.format(columns=columns))
        self.conn.commit()

    def create_derivation_wallet(self, coin):
        self.cur.execute(f"""
            CREATE TABLE IF NOT EXISTS wallet_derivation_{coin} ( 
            address_index TEXT,
            path TEXT,
            address TEXT,
            private_key TEXT,
            finger_print TEXT,
            FOREIGN KEY(finger_print) REFERENCES wallet_core(finger_print)
            )""")

        self.conn.commit()

    def insert_wallet_core(self, wallet_keys, wallet_values):
        query = ("INSERT INTO wallet_core ({fields}) VALUES ({marks})"
                 .format(fields=", ".join(wallet_keys),
                         marks=", ".join("?" * len(wallet_values))))

        self.cur.execute(query, wallet_values)
        self.conn.commit()

    def insert_wallet_derivation(self, coin, index, path, address, private_key, fingerprint):
        query = f"INSERT INTO wallet_derivation_{coin}(address_index, path, address, private_key, finger_print) VALUES " \
                f"(?,?,?,?,?) "
        self.cur.execute(query, (index, path, address, private_key, fingerprint))
        self.conn.commit()