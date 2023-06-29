from database import database_


def create_database(path, name):
    sql = """
            CREATE TABLE IF NOT EXISTS 
            SALT (salt_value)"""

    database_.execute_sql(sql, (), path, name)


def store_salt(salt, path, name):
    sql = """INSERT INTO SALT (salt_value) 
                        VALUES (?)"""
    args = (salt,)

    database_.execute_sql(sql, args, path, name)


def get_salt(path, name):
    sql = """SELECT (salt_value) from SALT"""

    result = database_.execute_sql(sql, (), path, name)
    return result[0]
