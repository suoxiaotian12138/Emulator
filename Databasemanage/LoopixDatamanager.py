import sqlite3
import os

from support_formats import Mix, Provider, Client
from Databasemanage.datamanager import *
from tools.Serialization import decode
from cryptography.hazmat.primitives import serialization

class LoopixDatamanager(Datamanager):

    def __init__(self, databaseName):
        db_file = os.getenv('DB_FILE', databaseName)
        self.db = sqlite3.connect(db_file)
        self.cursor = self.db.cursor()

    def create_clients_table(self, table_name):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS %s (
                id INTEGER PRIMARY KEY,
                name BLOB,
                port INTEGER,
                host TEXT,
                pubk BLOB,
                provider BLOB,
                UNIQUE(name, port, host)
            )
        ''' % table_name)
        self.db.commit()

    def create_providers_table(self, table_name):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS %s (
                id INTEGER PRIMARY KEY,
                name BLOB,
                port INTEGER,
                host TEXT,
                pubk BLOB,
                UNIQUE(name, port, host)
            )
        ''' % table_name)
        self.db.commit()

    def create_mixnodes_table(self, table_name):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS %s (
                id INTEGER PRIMARY KEY,
                name BLOB,
                port INTEGER,
                host TEXT,
                pubk BLOB,
                groupId INTEGER,
                UNIQUE(name, port, host, groupId)
            )
        ''' % table_name)
        self.db.commit()


    def drop_table(self, table_name):
        self.cursor.execute("DROP TABLE IF EXISTS %s" % table_name)

    def insert_row_into_table(self, table_name, params):
        insert_query = "INSERT OR IGNORE INTO %s VALUES (%s)" % (
            table_name, ', '.join('?' for _ in params)
        )
        self.cursor.execute(insert_query, params)
        self.db.commit()

    def select_all(self, table_name):
        self.cursor.execute("SELECT * FROM %s" % table_name)
        return self.cursor.fetchall()

    def select_all_mixnodes(self):
        mixes_info = self.select_all('Mixnodes')
        mixes = []
        for mix in mixes_info:
            mixes.append(Mix(mix[1], mix[2], mix[3], serialization.load_pem_public_key(mix[4].encode('utf-8')), mix[5]))
        return mixes

    def select_all_providers(self):
        providers_info = self.select_all('Providers')
        providers = []
        for prv in providers_info:
            providers.append(Provider(str(prv[1]), prv[2], str(prv[3]), serialization.load_pem_public_key(prv[4].encode('utf-8'))))
        return providers

    def select_all_clients(self, name):
        clients_info = self.select_all('Clients')
        clients = []
        for client in clients_info:
            if client[1] == name:  # 跳过自身
                continue
            provider = self.select_provider_by_name(client[5])
            clients.append(Client(str(client[1]), client[2], client[3], serialization.load_pem_public_key(client[4].encode('utf-8')), provider))
        return clients

    def select_provider_by_name(self, param_val):
        if param_val is not None:
            self.cursor.execute("SELECT * FROM Providers WHERE name = ?", [str(param_val)])
        else:
            self.cursor.execute("SELECT * FROM Providers ORDER BY RANDOM() LIMIT 1")

        plist = self.cursor.fetchone()

        return Provider(str(plist[1]), plist[2], str(plist[3]), serialization.load_pem_public_key(plist[4].encode('utf-8')))

    def count_rows(self, table_name):
        self.cursor.execute("SELECT Count(*) FROM %s" % table_name)
        return int(self.cursor.fetchone()[0])

    def close_connection(self):
        self.db.close()