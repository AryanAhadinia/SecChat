from database import database


def create_database():
    sql = """
            CREATE TABLE IF NOT EXISTS 
            GROUP_DB
            (group_id INTEGER PRIMARY KEY AUTOINCREMENT, 
            admin_user  varchar (50),
            FOREIGN KEY(admin_user) REFERENCES USER(username) 
                    ON DELETE RESTRICT  ON UPDATE RESTRICT
            )"""
    database.execute_sql(sql, ())
