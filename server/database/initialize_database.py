from database import group_database
from database import group_member_database
from database import key_ring_database
from database import message_database
from database import user_database


def create_tables():
    user_database.create_database()
    group_database.create_database()
    group_member_database.create_database()
    key_ring_database.create_database()
    message_database.create_database()


create_tables()
