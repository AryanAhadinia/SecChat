from database import database_
import base64
from cryptographicio import aes


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


def get_messages(path, name, username, password):
    sql = """SELECT * from MESSAGE WHERE
                src_user = ? or dst_user = ? """

    result = database_.execute_sql(sql, (username, username), path, name)

    aes_ = aes.AESCipher(password)
    for i in range(len(result)):
        result[i] = list(result[i])
        result[i][2] = base64.b64decode(aes_.decrypt(result[i][2]).encode()).decode()
        result[i] = tuple(result[i])

    return result


def add_message(path, name, src_user, dst_user, encrypted_context, group_name, password):
    sql = """INSERT INTO MESSAGE (src_user, dst_user, encrypted_content, group_name) 
                            VALUES (?, ?, ?, ?)"""
    
    aes_ = aes.AESCipher(password)
    encrypted_context = aes_.encrypt(base64.b64encode(encrypted_context.encode()).decode())

    args = (src_user, dst_user, encrypted_context, group_name)

    database_.execute_sql(sql, args, path, name)
