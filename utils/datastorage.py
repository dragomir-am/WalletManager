import sqlite3
import typing


class WorkspaceData:
    def __init__(self):
        self.conn = sqlite3.connect("database.db")
        self.conn.row_factory = sqlite3.Row  # Makes the data retrieved from the database accessible by their column name
        self.cursor = self.conn.cursor()

        self.cursor.execute("CREATE TABLE IF NOT EXISTS wallet (salt TEXT, passphrase TEXT, mnemonic TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user_credentials (username TEXT, password TEXT)")

        self.conn.commit()  # Saves the changes

    def save_credentials(self, username: str, password: str):
        
    def show_userdata(self):

    def save(self, table: str, data: typing.List[typing.Tuple]):

        """
        Erase the previous table content and record new data to it.
        :param table: The table name
        :param data: A list of tuples, the tuples elements must be ordered like the table columns
        :return:
        """

        # self.cursor.execute(f"DELETE FROM {table}")

        table_data = self.cursor.execute(f"SELECT * FROM {table}")

        columns = [description[0] for description in table_data.description]  # Lists the columns of the table

        # Creates the SQL insert statement dynamically
        sql_statement = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(['?'] * len(columns))})"

        self.cursor.executemany(sql_statement, data)
        self.conn.commit()

    def get(self, table: str) -> typing.List[sqlite3.Row]:

        """
        Get all the rows recorded for the table.
        :param table: The table name to get the rows from. e.g: strategies, watchlist
        :return: A list of sqlite3.Rows accessible like Python dictionaries.
        """

        self.cursor.execute(f"SELECT * FROM {table}")
        data = self.cursor.fetchall()

        return data

import hashlib
import sqlite3

conn = sqlite3.connect('user')
c = conn.cursor()


def create_table_wallet():
    c.execute('CREATE TABLE IF NOT EXISTS wallet (salt TEXT, passphrase TEXT, mnemonic TEXT)')


def data_entry():
    from main import get_seed as seed, get_salt as salt, get_passphrase as passphrase, get_mnemonic as mnemonic_string
    c.execute("INSERT INTO wallet VALUES (?,?,?)", (salt, passphrase, mnemonic_string))
    conn.commit()


def create_table_login():
    try:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INT, username TEXT, password TXT )')
        conn.commit()
        return {'status': 'Table created successfully'}
    except Exception as e:
        return {'Error', str(e)}


def insert(ref, username, password):
    try:
        c.execute("INSERT INTO credential_table_name values (?,?,?)", (ref, username, hashing(password)))
        conn.commit()
        return {'status': 'Data inserted successfully'}
    except Exception as e:
        return {'Error', str(e)}


def hashing(pwd):
    hash_object = hashlib.md5(bytes(str(pwd), encoding='utf-8'))
    hex_dig = hash_object.hexdigest()
    return hex_dig
