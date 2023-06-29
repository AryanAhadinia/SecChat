import base64

import rsa

from database import database


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


def initialize_key(username, public_key):
    sql = """INSERT INTO KEY_RING (username, public_key, is_valid) 
                        VALUES (?, ? , ?)"""
    public_key_string = base64.b64encode(public_key.save_pkcs1("PEM")).decode()
    args = (username, public_key_string, 1)

    database.execute_sql(sql, args)


def get_user_valid_key(username):
    sql = """SELECT public_key from KEY_RING WHERE 
                username = ? and is_valid = 1"""
    args = (username,)

    result = database.execute_sql(sql, args)
    public_key_string, = result[0]

    return rsa.PublicKey.load_pkcs1(base64.b64decode(public_key_string))

