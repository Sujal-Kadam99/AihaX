import os, sys, json
os.environ['JWT_SECRET_KEY'] = 'devsecretdevsecretdevsecret1234567890'
os.environ['DATABASE_URL'] = 'sqlite:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/db/aihax.db'
sys.path.insert(0, r'c:\Users\sujal\OneDrive\Documents\Desktop\Aihax')

from backend.models.database import get_session_factory, AgentLog, Scan

db = get_session_factory()()
logs = db.query(AgentLog).filter(AgentLog.message.like('%katana%')).order_by(AgentLog.created_at.desc()).limit(10).all()
print(f"Katana logs found: {len(logs)}")
for l in logs:
    print(f"[{l.agent_id}] {l.level}: {l.message[:200]}")

# Also check endpoints in Endpoint table
from backend.models.database import Endpoint
eps = db.query(Endpoint).all()
print(f"Endpoints in DB: {len(eps)}")
for e in eps:
    print(f"Endpoint: {e.normalized_url} | params: {e.query_parameters}")

db.close()
