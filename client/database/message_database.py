from database import database_


def create_database(path, name):
    sql = """
            CREATE TABLE IF NOT EXISTS 
            MESSAGE
            (message_id INTEGER PRIMARY KEY,
            src_user VARCHAR(50), 
            dst_user  VARCHAR(50),
            encrypted_content TXT)  
            """

    database_.execute_sql(sql, (), path, name)
