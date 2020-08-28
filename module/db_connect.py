import sqlite3

def get_data_bbdd(fields, hash, table, param):
    # Connection
    sqliteConnection = sqlite3.connect(r"C:\Users\Iván\Desktop\TFG Github\net_analyzer.py\db.sqlite3")
    cursor = sqliteConnection.cursor()


    # Execute query
    if hash != 0:
        cursor.execute("SELECT "+ fields +" FROM "+table+" WHERE hash != '" + hash + "';")
    elif param!= 0:
        cursor.execute("SELECT " + fields + " FROM " + table +" "+ param+";")
    else:
        cursor.execute("SELECT " + fields + " FROM " + table+";")
    # Parse
    results = cursor.fetchall()

    # Commit changes and close the connection
    sqliteConnection.commit()
    sqliteConnection.close()

    return results
