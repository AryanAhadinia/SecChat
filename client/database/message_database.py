from database import database_


def create_database(path, name):
    sql = """
            CREATE TABLE IF NOT EXISTS 
            MESSAGE
            (src_user VARCHAR(50), 
            dst_user  VARCHAR(50),
            encrypted_content TXT,
            group_name VARCHAR(50))  
            """

    database_.execute_sql(sql, (), path, name)


def get_messages(path, name, username):
    sql = """SELECT * from MESSAGE WHERE
                src_user = ? or dst_user = ? """

    result = database_.execute_sql(sql, (username, username), path, name)
    return result


def add_message(path, name, src_user, dst_user, encrypted_context, group_name):
    sql = """INSERT INTO MESSAGE (src_user, dst_user, encrypted_content, group_name) 
                            VALUES (?, ?, ?, ?)"""
    args = (src_user, dst_user, encrypted_context, group_name)

    database_.execute_sql(sql, args, path, name)
