import base64
import json
import os
from flask import Flask, request, jsonify, make_response, send_from_directory
from lxml import etree
import jwt

app = Flask(__name__)

# Directory for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# 0. Index / Navigation Hub
@app.route('/')
def index():
    return """<!DOCTYPE html>
<html>
<head><title>Vulnerable Target Portal</title></head>
<body>
    <h1>Application Portal</h1>
    <nav>
        <ul>
            <li><a href="/login">Login Page</a></li>
            <li><a href="/admin">Admin Console</a></li>
            <li><a href="/transfer">Funds Transfer</a></li>
            <li><a href="/upload">File Upload Service</a></li>
            <li><a href="/parse-xml">XML Processing Service</a></li>
            <li><a href="/files/">Public Static Files</a></li>
            <li><a href="/api/data">API Data Endpoint</a></li>
            <li><a href="/error-page">System Diagnostics / Error Page</a></li>
        </ul>
    </nav>
    <form action="/transfer" method="POST">
        <input type="text" name="amount" value="100"/>
        <input type="text" name="to_account" value="attacker"/>
        <button type="submit">Transfer</button>
    </form>
</body>
</html>"""


# 1. CSRF (Vulnerable by design: state changing POST without token)
@app.route('/transfer', methods=['POST'])
def transfer():
    # Vulnerable: No CSRF token checked
    amount = request.form.get('amount', 0)
    to_account = request.form.get('to_account', '')
    return jsonify({"status": "success", "message": f"Transferred {amount} to {to_account}"})


# 2. CORS (Vulnerable by design: reflects Origin with ACAC: true)
@app.route('/api/data', methods=['GET', 'OPTIONS'])
def api_data():
    resp = make_response(jsonify({"sensitive_data": "secret_123"}))
    origin = request.headers.get('Origin')
    if origin:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


# 3. JWT (Vulnerable by design: accepts alg:none)
@app.route('/admin', methods=['GET'])
def admin():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing token"}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # Decode header to check alg
        header_b64 = token.split('.')[0]
        # Pad if necessary
        header_b64 += '=' * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8'))
        
        alg = header.get('alg', '').lower()
        if alg == 'none':
            # Vulnerable: Accepts unverified token if alg is none
            payload_b64 = token.split('.')[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        else:
            # Would normally verify signature here, but we'll reject for simplicity if not none (or pretend we verify)
            payload = jwt.decode(token, "secret", algorithms=["HS256"])

        if payload.get('role') == 'admin':
            return jsonify({"status": "success", "message": "Welcome Admin!"})
        else:
            return jsonify({"error": "Forbidden"}), 403

    except Exception as e:
        return jsonify({"error": f"Invalid token: {e}"}), 401


# 4. File Upload (Vulnerable by design: allows any file, serves statically)
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # Vulnerable: No extension/type validation, saving directly
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    return jsonify({"status": "success", "url": f"/uploads/{file.filename}"})

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# 5. XXE (Vulnerable by design: external entities enabled)
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # Mock vulnerable Linux server on Windows: Check before parsing so lxml doesn't crash on missing /etc/passwd
    if b"file:///etc/passwd" in xml_data:
        return jsonify({"status": "success", "content": "root:x:0:0:root:/root:/bin/bash\n"})
    try:
        # We use lxml with huge_tree=True and resolve_entities=True to simulate vulnerability
        parser = etree.XMLParser(resolve_entities=True, huge_tree=True)
        root = etree.fromstring(xml_data, parser)
        return jsonify({"status": "success", "content": "".join(root.itertext())})
    except Exception as e:
        return jsonify({"error": f"XML parse error: {e}"}), 400


# 6. Directory Listing (Vulnerable by design: returns Apache-style listing)
@app.route('/files/')
def directory_listing():
    listing = """<html><head><title>Index of /files/</title></head>
<body><h1>Index of /files/</h1>
<pre><a href="?C=N;O=D">Name</a>  <a href="?C=M;O=A">Last modified</a>  <a href="?C=S;O=A">Size</a>
<hr>
<a href="../">Parent Directory</a>    -
<a href=".env">.env</a>              2026-09-01 10:00   1.2K
<a href="config.json">config.json</a>       2026-09-01 10:00   3.4K
<a href="backup.sql">backup.sql</a>        2026-09-01 10:00   45M
<a href="logo.png">logo.png</a>          2026-09-01 10:00   128K
<hr></pre></body></html>"""
    return listing, 200


# 7. Verbose Error / Stack Trace Leak (Vulnerable by design: debug mode on)
@app.route('/error-page')
def error_page():
    # Simulate a Python traceback leak
    probe = request.args.get('aihax_error_probe[]', request.args.get('id', None))
    if probe:
        traceback_output = """Traceback (most recent call last):
  File "/home/deploy/app/main.py", line 42, in handler
    result = db.query(user_id=probe)
  File "/home/deploy/app/database.py", line 98, in query
    cursor.execute(sql, params)
psycopg2.errors.SyntaxError: syntax error at or near "'"
LINE 1: SELECT * FROM users WHERE id = '''
                                        ^"""
        return f"<html><body><h1>Internal Server Error</h1><pre>{traceback_output}</pre></body></html>", 500
    return "<html><body>OK</body></html>", 200


# 8. Default Credentials Login (Vulnerable by design: accepts admin/admin)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '<html><body><form method="POST"><input name="username"/><input name="password" type="password"/><button>Login</button></form></body></html>'
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Vulnerable: accepts default credentials
    if username == 'admin' and password in ('admin', 'password', '123456'):
        resp = make_response('<html><body>Welcome to your Dashboard! <a href="/logout">Logout</a></body></html>')
        resp.set_cookie('session', 'authenticated_admin_session_abc123', path='/')
        return resp
    
    return '<html><body>Login failed. Invalid username or password. <form method="POST"><input name="username"/><input name="password" type="password"/><button>Login</button></form></body></html>', 200


if __name__ == '__main__':
    app.run(port=5005)

