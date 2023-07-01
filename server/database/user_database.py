from database import database


def create_database():
    sql = """
                CREATE TABLE IF NOT EXISTS 
                USER
                (username VARCHAR(50) PRIMARY KEY,
                hashed_password TXT NOT NULL,
                salt TXT NOT NULL)"""
    database.execute_sql(sql, ())


def register_user(username, hashed_password, salt):
    sql = """SELECT * from USER WHERE username = ?"""
    args = (username,)
    result = database.execute_sql(sql, args)
    if len(result) != 0:
        return False

    sql = """INSERT INTO USER (username, hashed_password, salt) 
                    VALUES (?, ?, ?)"""
    args = (username, hashed_password, salt)

    database.execute_sql(sql, args)

    return True

def username_exists(user_name):
    sql = """SELECT * from USER WHERE username = ?"""
    args = (user_name,)
    result = database.execute_sql(sql, args)
    print(result)
    if len(result) != 0:
        return True
    return False

def login_user(username, hashed_password):
    sql = """SELECT * from USER WHERE username = ? and hashed_password = ?"""
    args = (username, hashed_password)
    result = database.execute_sql(sql, args)
    if len(result) != 0:
        return True
    return False
