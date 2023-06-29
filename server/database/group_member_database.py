from database import database


def create_database():
    create_sql = """
            CREATE TABLE IF NOT EXISTS 
            GROUP_MEMBER
            (group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username  VARCHAR (50),
            FOREIGN KEY(username) REFERENCES USER(username) ON DELETE RESTRICT  ON UPDATE RESTRICT);
            """
    index_sql1 = """CREATE UNIQUE INDEX IF NOT EXISTS  idx_group_id ON GROUP_MEMBER (group_id);"""
    index_sql2 = """CREATE UNIQUE INDEX IF NOT EXISTS  idx_username ON GROUP_MEMBER (username);"""

    database.execute_sql(create_sql, ())
    database.execute_sql(index_sql1, ())
    database.execute_sql(index_sql2, ())
