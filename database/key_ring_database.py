import database


def create_database():
    sql = """
            CREATE TABLE IF NOT EXISTS 
            KEY_RING
            (username VARCHAR(50), 
            public_key TXT, 
            is_valid INTEGER , 
            creation_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
            CHECK (is_valid IN (0, 1)), 
            FOREIGN KEY(username) REFERENCES USER(username) ON DELETE RESTRICT  ON UPDATE RESTRICT)  """

    database.execute_sql(sql, ())
