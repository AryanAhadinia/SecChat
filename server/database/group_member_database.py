from database import database


def create_database():
    create_sql = """\
        CREATE TABLE IF NOT EXISTS 
        GROUP_MEMBER
        (
			group_id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR (50),
			FOREIGN KEY(group_id) REFERENCES GROUP_DB(group_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
			FOREIGN KEY(username) REFERENCES USER(username) ON DELETE CASCADE ON UPDATE CASCADE
    	);
    """
    index_sql1 = (
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_group_id ON GROUP_MEMBER (group_id);"""
    )
    index_sql2 = (
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_username ON GROUP_MEMBER (username);"""
    )

    database.execute_sql(create_sql, ())
    database.execute_sql(index_sql1, ())
    database.execute_sql(index_sql2, ())


def add_user_to_group(group_id, username):
    sql = """INSERT INTO GROUP_MEMBER (group_id, username) VALUES (?, ?);"""
    args = (group_id, username)
    database.execute_sql(sql, args)


def remove_user_from_group(group_id, username):
    sql = """DELETE FROM GROUP_MEMBER WHERE group_id = ? AND username = ?;"""
    args = (group_id, username)
    database.execute_sql(sql, args)


def get_group_members(group_id):
    sql = """SELECT username FROM GROUP_MEMBER WHERE group_id = ?;"""
    args = (group_id,)
    return database.execute_sql(sql, args)


def get_groups_for_user(username):
    sql = """SELECT GROUP_DB.group_id, GROUP_DB.name FROM GROUP_MEMBER JOIN GROUP_DB ON GROUP_MEMBER.group_id = GROUP_DB.group_id WHERE GROUP_MEMBER.username = ?;"""
    args = (username,)
    return database.execute_sql(sql, args)
