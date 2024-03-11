import sqlite3

conn = sqlite3.connect('instance/users.db')

cur = conn.cursor()

sql = "DELETE FROM preference WHERE id = 2"

cur.execute(sql)

conn.commit()

conn.close()
