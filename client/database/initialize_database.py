from database import salt_database
from database import message_database


def create_tables(path, name):
    salt_database.create_database(path, name)
    message_database.create_database(path, name)
