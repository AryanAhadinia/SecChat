import sqlite3


def execute_sql(sql, args):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(sql, args)
    conn.commit()
    conn.close()
