import database


def create_database():
    sql = """
                CREATE TABLE IF NOT EXISTS 
                USER
                (username VARCHAR(50) PRIMARY KEY,
                hashed_password TXT NOT NULL,
                salt TXT NOT NULL)"""
    database.execute_sql(sql, ())


def register_user(username, hashed_password, salt):
    sql = """INSERT INTO USER (username, hashed_password, salt) 
                    VALUES (?, ?, ?)"""
    args = (username, hashed_password, salt)

    database.execute_sql(sql, args)

#
# database.create_database()
# database.register_user("h", "i", "dd")
