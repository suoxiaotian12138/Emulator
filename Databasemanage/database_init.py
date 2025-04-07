from Databasemanage.LoopixDatamanager import LoopixDatamanager







def loopix_database_initial():
    dbManager = LoopixDatamanager("database.db")

    dbManager.create_clients_table("Clients")
    dbManager.create_mixnodes_table("Mixnodes")
    dbManager.create_providers_table("Providers")