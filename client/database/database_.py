import os
import sqlite3
import os


def execute_sql(sql, args, path, name):
    conn = sqlite3.connect(os.path.join(path, name))
    cursor = conn.cursor()
    cursor.execute(sql, args)
    conn.commit()
    result = cursor.fetchall() 
    conn.close()
    return result
