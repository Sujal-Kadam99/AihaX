import sqlite3
import json

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

conn = sqlite3.connect('db/aihax.db')
conn.row_factory = dict_factory
cursor = conn.cursor()

out = {}

# Check what tables exist
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [r['name'] for r in cursor.fetchall()]

if 'campaigns' in tables:
    cursor.execute("SELECT * FROM campaigns WHERE status IN ('AUTHORIZED', 'RUNNING');")
    out['campaigns'] = cursor.fetchall()
else:
    print("NO CAMPAIGNS TABLE")

if 'authorization_records' in tables:
    cursor.execute("SELECT * FROM authorization_records;")
    out['authorization_records'] = cursor.fetchall()

if 'scope_snapshots' in tables:
    cursor.execute("SELECT * FROM scope_snapshots;")
    out['scope_snapshots'] = cursor.fetchall()

print(json.dumps(out, indent=2))
