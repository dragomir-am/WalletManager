import sqlite3


class Wallet_db:

    def __init__(self):
        self.conn = sqlite3.connect("wallets.db")
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()

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
        query = f"INSERT INTO wallet_derivation_{coin}(address_index, path, address, private_key, finger_print) VALUES "\
                f"(?,?,?,?,?) "
        self.cur.execute(query, (index, path, address, private_key, fingerprint))
        self.conn.commit()

