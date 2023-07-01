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


def get_salt(username):
    sql = """SELECT salt from USER WHERE username = ?"""
    args = (username,)
    result = database.execute_sql(sql, args)
    if len(result) != 0:
        return result[0][0]
    return None


def update_password(username, hashed_password):
    sql = """UPDATE USER SET hashed_password = ? WHERE username = ?"""
    args = (hashed_password, username)
    database.execute_sql(sql, args)
