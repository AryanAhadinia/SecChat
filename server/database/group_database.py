from database import database


def create_database():
    sql = """
		CREATE TABLE IF NOT EXISTS 
		GROUP_DB
		(
			group_id INTEGER PRIMARY KEY AUTOINCREMENT, 
			name VARCHAR (50) NOT NULL UNIQUE,
			admin_user VARCHAR (50) NOT NULL,
			FOREIGN KEY(admin_user) REFERENCES USER(username) ON DELETE RESTRICT ON UPDATE RESTRICT
		);
    """
    database.execute_sql(sql, ())


def add_group(name, admin_user):
    sql = """INSERT INTO GROUP_DB (name, admin_user) VALUES (?, ?);"""
    args = (name, admin_user)
    database.execute_sql(sql, args)


def get_group_id(name):
    sql = """SELECT group_id FROM GROUP_DB WHERE name = ?;"""
    args = (name,)
    return database.execute_sql(sql, args)[0][0]


def get_group_admin(group_id):
    sql = """SELECT admin_user FROM GROUP_DB WHERE group_id = ?;"""
    args = (group_id,)
    return database.execute_sql(sql, args)[0][0]
