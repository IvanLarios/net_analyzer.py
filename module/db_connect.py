import sqlite3
import time

def get_data_bbdd(path,fields, hash, table, param):
    # Connection
    sqliteConnection = sqlite3.connect(path)
    cursor = sqliteConnection.cursor()
    print("Conected to the database, executing Query ")
    start = time.time()
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
    print("Query executed in " + str(time.time()-start)+" seconds.")
    return results
