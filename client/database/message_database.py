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
            group_name VARCHAR(50),
            sign TXT
            );  
            """

    database_.execute_sql(sql, (), path, name)


def get_messages(path, name, username, password):
    sql = """SELECT * from MESSAGE WHERE
                src_user = ? or dst_user = ? """

    result = database_.execute_sql(sql, (username, username), path, name)

    aes_ = aes.AESCipher(password)
    for i in range(len(result)):
        result[i] = list(result[i])
        result[i].pop()
        result[i][2] = base64.b64decode(aes_.decrypt(result[i][2]).encode()).decode()
        result[i] = tuple(result[i])

    return result


def add_message(path, name, src_user, dst_user, encrypted_context, group_name, sign, password):
    sql = """INSERT INTO MESSAGE (src_user, dst_user, encrypted_content, group_name, sign) 
                            VALUES (?, ?, ?, ?, ?)"""
    
    aes_ = aes.AESCipher(password)
    encrypted_context = aes_.encrypt(base64.b64encode(encrypted_context.encode()).decode())

    args = (src_user, dst_user, encrypted_context, group_name, sign)

    database_.execute_sql(sql, args, path, name)


def re_encrypt_messages(path, name, old_password, new_password):
    # get all messages, decrypt them, encrypt them with new password, update them
    sql = """SELECT * from MESSAGE"""

    result = database_.execute_sql(sql, (), path, name)

    aes_old = aes.AESCipher(old_password)
    aes_new = aes.AESCipher(new_password)
    for i in range(len(result)):
        result[i] = list(result[i])
        result[i][2] = base64.b64decode(aes_old.decrypt(result[i][2]).encode()).decode()
        result[i][2] = aes_new.encrypt(base64.b64encode(result[i][2].encode()).decode())
        result[i] = tuple(result[i])

    sql = """DELETE FROM MESSAGE"""
    database_.execute_sql(sql, (), path, name)

    sql = """INSERT INTO MESSAGE (src_user, dst_user, encrypted_content, group_name, sign)
                            VALUES (?, ?, ?, ?, ?)"""
    
    for i in range(len(result)):
        database_.execute_sql(sql, result[i], path, name)
