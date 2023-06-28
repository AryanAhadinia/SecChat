import database


def create_database():
    sql = """
            CREATE TABLE IF NOT EXISTS 
            MESSAGE
            (message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_user VARCHAR(50), 
            dst_user  VARCHAR(50),
            content TXT,
            FOREIGN KEY(src_user) REFERENCES USER(username) ON DELETE RESTRICT  ON UPDATE RESTRICT, 
            FOREIGN KEY(dst_user) REFERENCES USER(username) ON DELETE RESTRICT  ON UPDATE RESTRICT)  
            """

    database.execute_sql(sql, ())
