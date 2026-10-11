"""Quick script to check agent logs and findings from the previous scan."""

import sqlite3

conn = sqlite3.connect("db/aihax.db")
c = conn.cursor()

# Get all scans
print("=== SCANS ===")
query = (
    "SELECT id, target_url, status, created_at, completed_at "
    "FROM scans ORDER BY created_at DESC"
)
c.execute(query)
for row in c.fetchall():
    print(f"  {row[0][:12]}... | {row[1]} | {row[2]} | {row[3]} -> {row[4]}")

scan_id = "a593d456-8901-4ea7-b6a8-1d643c0b65d0"

# Get agent logs
print(f"\n=== AGENT LOGS (scan {scan_id[:12]}...) ===")
log_query = (
    "SELECT agent_id, level, message FROM agent_logs WHERE scan_id = ? ORDER BY id"
)
c.execute(log_query, (scan_id,))
rows = c.fetchall()
for r in rows:
    print(f"  Agent {r[0]} [{r[1]}]: {r[2]}")
print(f"  Total: {len(rows)} logs")

# Get findings
print("\n=== FINDINGS ===")
c.execute(
    "SELECT id, title, severity, vuln_type FROM findings WHERE scan_id = ?",
    (scan_id,),
)
findings = c.fetchall()
for f in findings:
    print(f"  [{f[2]}] {f[1]} ({f[3]})")
print(f"  Total: {len(findings)} findings")

conn.close()

