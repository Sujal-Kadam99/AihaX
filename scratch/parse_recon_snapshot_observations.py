import os, sys, json
os.environ['JWT_SECRET_KEY'] = 'devsecretdevsecretdevsecret1234567890'
os.environ['DATABASE_URL'] = 'sqlite:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/db/aihax.db'
sys.path.insert(0, r'c:\Users\sujal\OneDrive\Documents\Desktop\Aihax')

from backend.models.database import get_session_factory, AgentLog

db = get_session_factory()()
log = db.query(AgentLog).filter(AgentLog.agent_id == 1, AgentLog.message.like('%observations%')).order_by(AgentLog.created_at.desc()).first()

if log:
    data = json.loads(log.message)
    obs = data.get("observations", [])
    print(f"Total observations: {len(obs)}")
    endpoints = [o for o in obs if o.get("category") == "ENDPOINT"]
    params = [o for o in obs if o.get("category") == "PARAMETER"]
    print(f"Endpoints count: {len(endpoints)}")
    for ep in endpoints:
        print(f"  EP: {ep.get('normalized_value')} (discovered_by: {ep.get('discovered_by')})")
    print(f"\nParameters count: {len(params)}")
    for p in params:
        print(f"  PARAM: {p.get('normalized_value')} | val: {p.get('value')} | meta: {p.get('metadata')} | disc: {p.get('discovered_by')}")
else:
    print("No recon log found")

db.close()
