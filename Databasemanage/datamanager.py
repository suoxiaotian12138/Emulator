import sqlite3
import os
from support_formats import Mix, Provider, Client



class Datamanager(object):
    def __init__(self,databaseName):
        db_file = os.getenv('DB_FILE', '/app/data/example.db')
        self.db = sqlite3.connect(db_file)
        self.cursor = self.db.cursor()
    """
    数据库控制的标准，根据需求在特定节点建立示例，获取网络的信息
    此类为所有数据库管理类的父类，仅定义部分通用的方法
    """
    def Create_table_Clients(self):
        table_name = "Clients"
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY,
                                    name blob,
                                    port integer,
                                    host text,
                                    pubk blob,
                                    provider blob)''' % table_name)
        self.db.commit()
        print("Table [%s] created succesfully." ) % table_name
    def Create_table_Servers(self):
        table_name = "Servers"
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY,
                                    name blob,
                                    port integer,
                                    host text,
                                    pubk blob,
                                    )''' % table_name)
        self.db.commit()
        print("Table [%s] created succesfully." ) % table_name

    def select_all(self, table_name):
        self.cursor.execute("SELECT * FROM %s" % table_name)
        return self.cursor.fetchall()

    def Select_all_Clients(self):
        clients_info = self.select_all('Clients')
        clients = []
        for client in clients_info:
            provider = self.select_provider_by_name(client[5])
            clients.append(Client(str(client[1]), client[2], client[3], petlib.pack.decode(client[4]), provider))
        return clients


    def insert_row_into_table(self, table_name, params):
        insert_query = "INSERT INTO %s VALUES (%s)" % (table_name, ', '.join('?' for p in params))
        self.cursor.execute(insert_query, params)
        self.db.commit()