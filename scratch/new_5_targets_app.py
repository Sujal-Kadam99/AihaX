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


if __name__ == '__main__':
    app.run(port=5005)
