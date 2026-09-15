import sqlite3

db_path = "db/aihax.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("==== CAMPAIGNS ====")
cursor.execute("SELECT * FROM campaigns")
for c in cursor.fetchall():
    print(dict(c))
