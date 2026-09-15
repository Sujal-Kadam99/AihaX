"""Test the recon-diagnostics endpoint with proper auth."""
import urllib.request
import json

# Step 1: Get auth token from local-only auth endpoint
try:
    token_req = urllib.request.Request('http://127.0.0.1:8000/api/auth/token')
    token_resp = urllib.request.urlopen(token_req)
    token_data = json.loads(token_resp.read().decode())
    token = token_data.get('token') or token_data.get('access_token')
    print(f"AUTH: Got token: {token[:20]}...")
except Exception as e:
    print(f"AUTH ERROR: {e}")
    token = None

# Step 2: Call recon-diagnostics with auth
if token:
    url = 'http://127.0.0.1:8000/api/campaigns/28be78cd-84ab-41a9-8c81-996e649d6434/recon-diagnostics'
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Bearer {token}')
    try:
        resp = urllib.request.urlopen(req)
        print(f"STATUS: {resp.status}")
        data = json.loads(resp.read().decode())
        print(f"\nTool Records ({len(data['tool_records'])} tools):")
        print("-" * 50)
        for name, rec in sorted(data['tool_records'].items()):
            status = rec.get('status', 'UNKNOWN')
            print(f"  {name:20s} = {status}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP ERROR: {e.code} {e.reason}")
        print(f"Body: {body}")
    except Exception as e:
        print(f"ERROR: {e}")
else:
    # Try without auth (should get 401)
    print("No token, testing unauthenticated access...")
    url = 'http://127.0.0.1:8000/api/campaigns/28be78cd-84ab-41a9-8c81-996e649d6434/recon-diagnostics'
    try:
        resp = urllib.request.urlopen(url)
        print(f"WARNING: Got {resp.status} without auth!")
    except urllib.error.HTTPError as e:
        print(f"EXPECTED: {e.code} {e.reason} (auth enforced)")
