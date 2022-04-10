import sqlite3


class Wallet_db:

    def __init__(self):
        self.conn = sqlite3.connect("wallets.db")
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()

    def create_wallet_table(self, wallet_keys):
        columns = ", ".join("{field} TEXT".format(field=field) for field in wallet_keys)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS wallets_details( id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
            {columns}
            )
            """.format(columns=columns))
        self.conn.commit()

    def insert_btc_wallet(self, wallet_keys, wallet_values):
        query = ("INSERT INTO wallets_details ({fields}) VALUES ({marks})"
                 .format(fields=", ".join(wallet_keys),
                         marks=", ".join("?" * len(wallet_values))))

        self.cur.execute(query, wallet_values)
        self.conn.commit()
