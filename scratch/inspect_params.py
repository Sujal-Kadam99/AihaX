import os, sys, json
os.environ['JWT_SECRET_KEY'] = 'devsecretdevsecretdevsecret1234567890'
os.environ['DATABASE_URL'] = 'sqlite:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/db/aihax.db'
sys.path.insert(0, r'c:\Users\sujal\OneDrive\Documents\Desktop\Aihax')

from backend.models.database import get_session_factory, ReconSnapshotRecord

db = get_session_factory()()
r = db.query(ReconSnapshotRecord).order_by(ReconSnapshotRecord.created_at.desc()).first()
if r:
    data = json.loads(r.snapshot_json) if r.snapshot_json else {}
    obs = data.get('observations', [])
    params = [o for o in obs if o.get('category') == 'PARAMETER']
    print(f"Total observations: {len(obs)}, Total PARAMETER observations: {len(params)}")
    for p in params:
        print(f"param: {p.get('normalized_value')} | metadata: {p.get('metadata')} | discovered_by: {p.get('discovered_by')}")
else:
    print("No ReconSnapshotRecord found")
db.close()
