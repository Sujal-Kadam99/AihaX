"""Realistic Security Lab Application for AihaX 77-Check Deep Validation.

Implements realistic multi-user, multi-endpoint web application behaviors:
- Multi-user authentication & session store (Anonymous, User A, User B, Admin)
- Object-level authorization boundaries (IDOR, BOLA, Mass Assignment)
- Vulnerable vs Secure application endpoints across all 7 OWASP vulnerability categories
- Deceptive / False-Positive resilience endpoints (Soft-404, Generic 500, Encoded Reflection, Public IDs)
- Safe internal callback receiver for SSRF validation (strictly in-scope loopback)
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from aiohttp import web


def create_security_lab_app() -> web.Application:
    app = web.Application()

    # In-memory realistic database & session store
    users_db = {
        "user_a": {"id": "1001", "name": "Alice User", "email": "alice@corp.internal", "balance": "$4,500.00", "role": "user"},
        "user_b": {"id": "1002", "name": "Bob Victim", "email": "bob@corp.internal", "balance": "$9,200.00", "role": "user"},
        "admin": {"id": "9999", "name": "Admin Root", "email": "admin@corp.internal", "balance": "$0.00", "role": "admin"},
    }
    active_tokens = {
        "token_alice_valid": "user_a",
        "token_bob_valid": "user_b",
        "token_admin_valid": "admin",
    }
    redeemed_coupons = set()
    replay_tokens_used = set()
    ssrf_callback_logs: List[Dict[str, Any]] = []

    # ──────────────────────────────────────────────────────────────────────────
    # 1. RECON & EXPOSURE HANDLERS (C001 - C011)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_root(request: web.Request) -> web.Response:
        return web.Response(text="Security Lab Root - Online", status=200)

    async def h_port_80_exposure(request: web.Request) -> web.Response:
        return web.Response(text="HTTP Port Open Without HTTPS Redirect", status=200)

    async def h_missing_security_headers(request: web.Request) -> web.Response:
        return web.Response(text="<html><body>Missing Security Headers Page</body></html>", status=200)

    async def h_sensitive_env(request: web.Request) -> web.Response:
        return web.Response(
            text="DB_HOST=127.0.0.1\nDB_PASSWORD=synthetic_secret_password_777\nSECRET_KEY=prod_synthetic_key\n",
            content_type="text/plain",
            status=200,
        )

    async def h_cors_misconfig(request: web.Request) -> web.Response:
        origin = request.headers.get("Origin", "*")
        return web.Response(
            text=json.dumps({"account": "alice", "balance": "$4,500.00"}),
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "application/json",
            },
            status=200,
        )

    async def h_graphql(request: web.Request) -> web.Response:
        if request.method == "POST":
            data = await request.text()
            if "__schema" in data:
                return web.Response(
                    text=json.dumps({
                        "data": {
                            "__schema": {
                                "types": [
                                    {"name": "User", "kind": "OBJECT"},
                                    {"name": "AdminQuery", "kind": "OBJECT"},
                                    {"name": "Mutation", "kind": "OBJECT"},
                                ]
                            }
                        }
                    }),
                    content_type="application/json",
                    status=200,
                )
        return web.Response(text=json.dumps({"message": "GraphQL API ready"}), content_type="application/json", status=200)

    async def h_directory_listing(request: web.Request) -> web.Response:
        return web.Response(
            text="""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /backups</title>
 </head>
 <body>
<h1>Index of /backups</h1>
<pre><a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr><a href="/">Parent Directory</a>                             -   
<a href="db_backup_2026.sql">db_backup_2026.sql</a>      2026-08-28 01:23  4.2M  
<a href="users_export.csv">users_export.csv</a>        2026-08-28 02:15  1.1M  
<hr></pre>
</body></html>""",
            content_type="text/html",
            status=200,
        )

    async def h_open_redirect(request: web.Request) -> web.Response:
        target = request.query.get("next") or request.query.get("url") or request.query.get("redirect") or "http://evil.com"
        return web.Response(status=302, headers={"Location": target})

    async def h_subdomain_takeover_dangling(request: web.Request) -> web.Response:
        # Realistic AWS S3 NoSuchBucket dangling error
        return web.Response(
            text="""<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
  <BucketName>aihax-dangling-bucket-demo</BucketName>
  <RequestId>4442587EXAMPLE</RequestId>
  <HostId>K1234567890EXAMPLE=</HostId>
</Error>""",
            content_type="application/xml",
            status=404,
        )

    async def h_actuator_health(request: web.Request) -> web.Response:
        return web.Response(
            text=json.dumps({
                "status": "UP",
                "components": {
                    "db": {"status": "UP", "details": {"database": "PostgreSQL", "validationQuery": "isValid()"}},
                    "diskSpace": {"status": "UP", "details": {"total": 107374182400, "free": 85899345920}},
                },
                "_links": {"self": {"href": "/actuator/health"}, "info": {"href": "/actuator/info"}},
            }),
            content_type="application/json",
            status=200,
        )

    async def h_tls_weakness(request: web.Request) -> web.Response:
        return web.Response(text="TLS Endpoint", headers={"Strict-Transport-Security": "max-age=300"}, status=200)

    async def h_tech_exposure(request: web.Request) -> web.Response:
        return web.Response(
            text="Web Portal",
            headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3", "X-AspNet-Version": "4.0.30319"},
            status=200,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 2. AUTHENTICATION & SESSION HANDLERS (C012 - C022)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_auth_bypass(request: web.Request) -> web.Response:
        # Override headers: X-Original-URL, X-Rewrite-URL, X-Forwarded-For
        if request.headers.get("X-Original-URL") in ("/admin", "/admin/dashboard") or request.headers.get("X-Forwarded-For") == "127.0.0.1":
            return web.Response(text="Welcome Administrator! Administrative Panel Access Granted.", status=200)
        return web.Response(text="HTTP 401 Unauthorized: Authentication required for /admin", status=401)

    async def h_weak_cookie(request: web.Request) -> web.Response:
        resp = web.Response(text="Session established")
        resp.headers["Set-Cookie"] = "session_id=synthetic_session_12345; Domain=.corp.internal; Path=/"
        return resp

    async def h_missing_secure_cookie(request: web.Request) -> web.Response:
        resp = web.Response(text="Session established")
        resp.headers["Set-Cookie"] = "auth_token=synthetic_auth_token_999; HttpOnly; SameSite=Lax"
        return resp

    async def h_missing_httponly_cookie(request: web.Request) -> web.Response:
        resp = web.Response(text="Session established")
        resp.headers["Set-Cookie"] = "auth_token=synthetic_auth_token_999; Secure; SameSite=Lax"
        return resp

    async def h_missing_samesite_cookie(request: web.Request) -> web.Response:
        resp = web.Response(text="Session established")
        resp.headers["Set-Cookie"] = "auth_token=synthetic_auth_token_999; Secure; HttpOnly"
        return resp

    async def h_session_fixation(request: web.Request) -> web.Response:
        sess = request.query.get("sessionid") or request.query.get("sid") or "new_session_random_888"
        resp = web.Response(text=f"Session Active: {sess}")
        resp.headers["Set-Cookie"] = f"sessionid={sess}; Path=/; HttpOnly"
        return resp

    async def h_logout_invalidation(request: web.Request) -> web.Response:
        if request.path.endswith("/logout"):
            # Logout claims success but doesn't revoke session token in backend
            return web.Response(text=json.dumps({"message": "Successfully logged out"}), content_type="application/json", status=200)
        # Profile endpoint continues accepting old session token
        auth = request.headers.get("Authorization", "")
        if "token_alice_valid" in auth or "Bearer " in auth:
            return web.Response(text=json.dumps({"user": "alice", "profile": "active", "warning": "session_not_revoked"}), content_type="application/json", status=200)
        return web.Response(text="Unauthorized", status=401)

    async def h_password_policy(request: web.Request) -> web.Response:
        return web.Response(
            text='<html><body><form action="/register" method="POST"><input type="password" name="password" minlength="3"><button type="submit">Sign Up</button></form></body></html>',
            content_type="text/html",
            status=200,
        )

    async def h_jwt_validation(request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return web.Response(text="HTTP 401 Unauthorized: Bearer token required", status=401)
        token = auth.split("Bearer ", 1)[1].strip()

        # Reject invalid garbage token
        if "invalid.garbage" in token:
            return web.Response(text="HTTP 401 Unauthorized: Invalid token signature", status=401)

        # Vulnerable parser accepts unsigned alg: none
        if "eyJhbGciOiJub25l" in token or "eyJhbGciOiAibm9uZSI" in token:
            return web.Response(
                text=json.dumps({"status": "authenticated", "role": "admin", "privilege": "full", "message": "Accepted alg: none"}),
                content_type="application/json",
                status=200,
            )

        # Vulnerable parser accepts expired token
        if "user_audit" in token or "eyJleHAiOjE1Nzc4MzY4MDB" in token:
            return web.Response(
                text=json.dumps({"status": "authenticated", "user": "user_audit", "message": "Expired token accepted without exp validation"}),
                content_type="application/json",
                status=200,
            )

        return web.Response(text=json.dumps({"status": "authenticated", "user": "alice"}), content_type="application/json", status=200)

    async def h_auth_rate_limit(request: web.Request) -> web.Response:
        # Always returns 401 without rate limiting (no 429 after multiple attempts)
        return web.Response(text=json.dumps({"error": "Invalid username or password"}), content_type="application/json", status=401)

    # ──────────────────────────────────────────────────────────────────────────
    # 3. INJECTION HANDLERS (C023 - C036)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_sqli(request: web.Request) -> web.Response:
        p = request.query.get("id", "1")
        if "'" in p or '"' in p or "--" in p or "OR 1=1" in p:
            return web.Response(
                text="MySQL Error: You have an error in your SQL syntax near '' at line 1 in /var/www/query.php",
                status=200,
            )
        return web.Response(text=f"Product record ID {p}: Laptop Model X, Price $1,299", status=200)

    async def h_blind_sqli(request: web.Request) -> web.Response:
        p = request.query.get("id", "1")
        if "AND 1=1" in p or "1=1" in p:
            return web.Response(
                text="<html><body><h1>Inventory Database</h1><p>Full item description with comprehensive specification details and manufacturer specifications.</p></body></html>",
                content_type="text/html",
                status=200,
            )
        elif "AND 1=2" in p or "1=2" in p:
            return web.Response(text="<html><body><h1>No Records Found</h1></body></html>", content_type="text/html", status=200)
        return web.Response(
            text="<html><body><h1>Inventory Database</h1><p>Full item description with comprehensive specification details and manufacturer specifications.</p></body></html>",
            content_type="text/html",
            status=200,
        )

    async def h_nosqli(request: web.Request) -> web.Response:
        # Handle query parameter check
        query_str = str(request.rel_url)
        if "[$ne]" in query_str or any("[$ne]" in k for k in request.query.keys()):
            return web.Response(text="MongoError: Cast to ObjectId failed for value [$ne] at path '_id'", status=200)
        return web.Response(text=json.dumps({"user": "guest"}), content_type="application/json", status=200)

    async def h_cmdi(request: web.Request) -> web.Response:
        cmd = request.query.get("cmd", "")
        if ";" in cmd or "|" in cmd or "`" in cmd or "$(" in cmd:
            return web.Response(text="/bin/sh: 1: syntax error near unexpected token `|'\n", status=200)
        return web.Response(text="Command status: idle", status=200)

    async def h_os_cmdi(request: web.Request) -> web.Response:
        ip = request.query.get("ip", "127.0.0.1")
        # In-process safe calculation simulation for arithmetic canaries
        output = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
        if "31330" in ip and "7" in ip:
            output += "31337\n"
        elif "54310" in ip and "11" in ip:
            output += "54321\n"
        return web.Response(text=output, status=200)

    async def h_ssti(request: web.Request) -> web.Response:
        name = request.query.get("name", "Guest")
        # In-process template engine math evaluation
        rendered = name
        if "{{31330+7}}" in name or "${31330+7}" in name or "<%= 31330+7 %>" in name:
            rendered = "Hello 31337! Welcome to the template portal."
        elif "{{7*7}}" in name or "${7*7}" in name:
            rendered = "Hello 49! Welcome to the template portal."
        else:
            rendered = f"Hello {name}! Welcome to the template portal."
        return web.Response(text=rendered, content_type="text/html", status=200)

    async def h_header_injection(request: web.Request) -> web.Response:
        name = request.query.get("name", "standard")
        resp = web.Response(text=f"Hello {name}")
        if "x-aihax-canary" in str(request.rel_url).lower() or "probe123" in str(request.rel_url):
            resp.headers["X-AihaX-Canary"] = "probe123"
        elif "%0d%0a" in name.lower() or "\r\n" in name:
            resp.headers["X-Injected-Header"] = "synthetic_canary_value"
        return resp

    async def h_crlf_injection(request: web.Request) -> web.Response:
        url = request.query.get("url", "/")
        resp = web.Response(text=f"Redirecting to {url}", status=302)
        resp.headers["Location"] = url
        if "aihax_crlf_test" in str(request.rel_url):
            resp.headers["Set-Cookie"] = "aihax_crlf_test=injected_123; Path=/"
        elif "%0d%0aset-cookie" in url.lower() or "\r\nset-cookie" in url.lower():
            resp.headers["Set-Cookie"] = "injected_crlf_cookie=synthetic_canary_123"
        return resp

    async def h_path_traversal(request: web.Request) -> web.Response:
        f = request.query.get("file", "default.txt")
        if "etc/passwd" in f or "../" in f:
            return web.Response(
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
                content_type="text/plain",
                status=200,
            )
        return web.Response(text="Standard page content: documentation guide.", status=200)

    async def h_lfi(request: web.Request) -> web.Response:
        f = request.query.get("file", "index.php")
        if "php://filter" in f and "base64" in f:
            # Simulated base64-encoded source disclosure
            return web.Response(text="PD9waHAKLy8gU3ludGhldGljIFBIUCBTb3VyY2UgQ29kZSBFc3RhYmxpc2hlZCAyMDI2CmVjaG8gIkhlbGxvIFdvcmxkIjsKPz4=", status=200)
        return web.Response(text="Standard LFI view", status=200)

    async def h_xxe(request: web.Request) -> web.Response:
        if request.method == "POST":
            body = await request.text()
            if "aihax_xxe_proof_token_8899" in body:
                return web.Response(text="<root><name>aihax_xxe_proof_token_8899</name></root>", content_type="application/xml", status=200)
            elif "<!ENTITY" in body or "ENTITY" in body:
                return web.Response(text="XML Parsed Output: root:x:0:0:root:/root:/bin/bash\n", status=200)
        return web.Response(text="XML API endpoint", status=200)

    async def h_ldap(request: web.Request) -> web.Response:
        user = request.query.get("user", "")
        if "*" in user or "(|" in user:
            return web.Response(text="LDAP Error: Invalid DN syntax / search filter failed in ldap_search()", status=200)
        return web.Response(text="LDAP Directory: 0 matches", status=200)

    async def h_el_injection(request: web.Request) -> web.Response:
        expr = request.query.get("expr", "")
        if "31330+7" in expr or "31330 + 7" in expr:
            return web.Response(text="Expression Evaluated: 31337", status=200)
        return web.Response(text="Expression Engine Ready", status=200)

    async def h_ssrf_proxy(request: web.Request) -> web.Response:
        target_url = request.query.get("url", "")
        if not target_url:
            return web.Response(text="Missing url parameter", status=400)

        # Record outgoing SSRF probe internally for callback verification
        ssrf_callback_logs.append({"requested_target": target_url, "timestamp": asyncio.get_event_loop().time()})

        # If probing in-scope /robots.txt
        if "robots.txt" in target_url:
            return web.Response(text="User-agent: *\nDisallow: /admin\nDisallow: /internal-secret\n", status=200)
        return web.Response(text=f"Fetched content from {target_url}", status=200)

    # ──────────────────────────────────────────────────────────────────────────
    # 4. CROSS-SITE SCRIPTING (XSS) HANDLERS (C037 - C046)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_reflected_xss(request: web.Request) -> web.Response:
        q = request.query.get("q", "")
        return web.Response(text=f"<html><body><h1>Search Results</h1><p>You searched for: {q}</p></body></html>", content_type="text/html", status=200)

    async def h_dom_xss(request: web.Request) -> web.Response:
        return web.Response(
            text="""<html><body>
<h1>Client Portal</h1>
<script>
  var query = window.location.search;
  document.write(window.location.search);
</script>
</body></html>""",
            content_type="text/html",
            status=200,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 5. MISCONFIGURATION HANDLERS (C047 - C056)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_clickjacking(request: web.Request) -> web.Response:
        # Missing X-Frame-Options and CSP frame-ancestors
        return web.Response(text="<html><body><h1>Embedded Frame Portal</h1></body></html>", content_type="text/html", status=200)

    async def h_insecure_methods(request: web.Request) -> web.Response:
        if request.method == "TRACE":
            headers_dump = "\r\n".join(f"{k}: {v}" for k, v in request.headers.items())
            return web.Response(text=f"TRACE / HTTP/1.1\r\n{headers_dump}\r\n", status=200)
        return web.Response(text="Methods Endpoint", headers={"Allow": "GET, POST, TRACE, OPTIONS"}, status=200)

    async def h_file_upload(request: web.Request) -> web.Response:
        if request.method == "POST":
            body = await request.text()
            # Vulnerable upload endpoint accepts .php without validation
            if 'filename="aihax_audit_test.php"' in body or ".php" in body:
                return web.Response(
                    text=json.dumps({"status": "success", "file": "aihax_audit_test.php", "path": "/uploads/aihax_audit_test.php"}),
                    content_type="application/json",
                    status=201,
                )
        return web.Response(text="Upload form ready", status=200)

    # ──────────────────────────────────────────────────────────────────────────
    # 6. SENSITIVE DATA EXPOSURE HANDLERS (C057 - C066)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_exposed_keys(request: web.Request) -> web.Response:
        return web.Response(
            text="<html><script>const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'; const STRIPE_KEY = 'sk_live_synthetic_secret_token_123';</script></html>",
            content_type="text/html",
            status=200,
        )

    async def h_source_map(request: web.Request) -> web.Response:
        return web.Response(
            text='{"version":3,"file":"bundle.js","sources":["src/App.tsx","src/auth.ts"],"mappings":"AAAA;AAAA"}',
            content_type="application/json",
            status=200,
        )

    async def h_git_head(request: web.Request) -> web.Response:
        return web.Response(text="ref: refs/heads/master\n", content_type="text/plain", status=200)

    # ──────────────────────────────────────────────────────────────────────────
    # 7. BUSINESS LOGIC & ACCESS CONTROL HANDLERS (C067 - C077)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_idor_numeric(request: web.Request) -> web.Response:
        user_id = request.query.get("user_id") or request.query.get("id") or "1001"
        if user_id == "1002":
            # Disclosing Bob's private record
            return web.Response(
                text=json.dumps(users_db["user_b"]),
                content_type="application/json",
                status=200,
            )
        elif user_id == "1001":
            return web.Response(text=json.dumps(users_db["user_a"]), content_type="application/json", status=200)
        return web.Response(text=json.dumps({"error": "User not found"}), content_type="application/json", status=404)

    async def h_mass_assignment(request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Vulnerable mass assignment: Binds is_admin and role directly into model
        record = {
            "name": data.get("name", "Default User"),
            "email": data.get("email", "user@example.com"),
            "is_admin": data.get("is_admin", False),
            "role": data.get("role", "user"),
            "admin": data.get("admin", False),
        }
        return web.Response(text=json.dumps(record), content_type="application/json", status=201)

    async def h_race_condition(request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            data = {}
        coupon = data.get("token") or "generic_coupon"
        # Vulnerable to concurrency: No database lock, allows multiple parallel requests to redeem same token
        await asyncio.sleep(0.01)  # Context switch opportunity for concurrent requests
        return web.Response(
            text=json.dumps({"success": True, "action": "redeemed", "coupon": coupon}),
            content_type="application/json",
            status=200,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 8. NEGATIVE CONTROLS (SECURE APPLICATION BASELINE)
    # ──────────────────────────────────────────────────────────────────────────

    async def h_secure_application(request: web.Request) -> web.Response:
        return web.Response(
            text="<html><body><h1>Secure Enterprise Application</h1><p>All inputs parameterized, headers enforced.</p></body></html>",
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Access-Control-Allow-Origin": "https://trusted-partner.com",
            },
            content_type="text/html",
            status=200,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 9. DECEPTIVE & FALSE-POSITIVE CONTROLS
    # ──────────────────────────────────────────────────────────────────────────

    async def h_deceptive_sqli_500(request: web.Request) -> web.Response:
        return web.Response(
            text="<html><body><h1>500 Internal Server Error</h1><p>An unexpected generic server exception occurred.</p></body></html>",
            content_type="text/html",
            status=500,
        )

    async def h_deceptive_xss_encoded(request: web.Request) -> web.Response:
        q = request.query.get("q", "")
        safe_q = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
        return web.Response(
            text=f"<html><body><h1>Search Results</h1><p>You searched for: {safe_q}</p></body></html>",
            content_type="text/html",
            status=200,
        )

    async def h_deceptive_soft_404(request: web.Request) -> web.Response:
        return web.Response(
            text="<html><head><title>404 Page Not Found</title></head><body><h1>Oops! The document you requested does not exist.</h1></body></html>",
            content_type="text/html",
            status=200,
        )

    async def h_deceptive_admin_login(request: web.Request) -> web.Response:
        return web.Response(
            text="""<html><body>
<h1>Admin Portal Login</h1>
<form action="/login" method="POST">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Log In</button>
</form>
</body></html>""",
            content_type="text/html",
            status=200,
        )

    async def h_deceptive_public_products(request: web.Request) -> web.Response:
        pid = request.query.get("id", "1")
        # Public product catalog with numeric IDs -> NOT IDOR
        return web.Response(
            text=json.dumps({"product_id": pid, "title": f"Public Product SKU #{pid}", "price": "$19.99", "public": True}),
            content_type="application/json",
            status=200,
        )

    async def h_health(request: web.Request) -> web.Response:
        return web.Response(text=json.dumps({"status": "ok", "app": "AihaX Safe Local Fixture"}), content_type="application/json", status=200)

    async def h_security_test(request: web.Request) -> web.Response:
        return web.Response(
            text="<html><head><title>AihaX Local Security Fixture</title></head><body><h1>Controlled Local Target</h1><p>Deterministic loopback verification target.</p></body></html>",
            content_type="text/html",
            status=200,
        )

    async def h_robots(request: web.Request) -> web.Response:
        return web.Response(
            text="User-agent: *\nDisallow: /admin\nDisallow: /backups\n",
            content_type="text/plain",
            status=200,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # ROUTE REGISTRATIONS
    # ──────────────────────────────────────────────────────────────────────────

    # Standard Local Diagnostic & Test Endpoints
    app.router.add_get("/health", h_health)
    app.router.add_get("/security-test", h_security_test)
    app.router.add_get("/robots.txt", h_robots)

    # Category A: Recon
    app.router.add_get("/", h_root)
    app.router.add_get("/vulnerable/c001_port_80", h_port_80_exposure)
    app.router.add_get("/vulnerable/c002_missing_headers", h_missing_security_headers)
    app.router.add_get("/.env", h_sensitive_env)
    app.router.add_get("/vulnerable/c004_cors", h_cors_misconfig)
    app.router.add_post("/graphql", h_graphql)
    app.router.add_post("/api/graphql", h_graphql)
    app.router.add_post("/vulnerable/c005_graphql", h_graphql)
    app.router.add_get("/vulnerable/c006_dir_listing/", h_directory_listing)
    app.router.add_get("/vulnerable/c007_redirect", h_open_redirect)
    app.router.add_get("/vulnerable/c008_takeover", h_subdomain_takeover_dangling)
    app.router.add_get("/actuator", h_actuator_health)
    app.router.add_get("/actuator/health", h_actuator_health)
    app.router.add_get("/vulnerable/c010_tls", h_tls_weakness)
    app.router.add_get("/vulnerable/c011_tech", h_tech_exposure)

    # Category B: Auth
    app.router.add_get("/vulnerable/c012_auth_bypass", h_auth_bypass)
    app.router.add_get("/vulnerable/c013_weak_cookie", h_weak_cookie)
    app.router.add_get("/vulnerable/c014_missing_secure", h_missing_secure_cookie)
    app.router.add_get("/vulnerable/c015_missing_httponly", h_missing_httponly_cookie)
    app.router.add_get("/vulnerable/c016_missing_samesite", h_missing_samesite_cookie)
    app.router.add_get("/vulnerable/c017_session_fixation", h_session_fixation)
    app.router.add_post("/logout", h_logout_invalidation)
    app.router.add_post("/vulnerable/logout", h_logout_invalidation)
    app.router.add_get("/vulnerable/c018_profile", h_logout_invalidation)
    app.router.add_get("/vulnerable/c019_password_policy", h_password_policy)
    app.router.add_post("/register", lambda r: web.Response(text=json.dumps({"status": "created"}), content_type="application/json", status=201))
    app.router.add_post("/api/register", lambda r: web.Response(text=json.dumps({"status": "created"}), content_type="application/json", status=201))
    app.router.add_get("/vulnerable/c020_jwt", h_jwt_validation)
    app.router.add_get("/vulnerable/c021_jwt", h_jwt_validation)
    app.router.add_post("/login", h_auth_rate_limit)
    app.router.add_post("/api/login", h_auth_rate_limit)
    app.router.add_post("/vulnerable/c022_login", h_auth_rate_limit)

    # Category C: Injection
    app.router.add_get("/vulnerable/c023_sqli", h_sqli)
    app.router.add_get("/vulnerable/c024_blind_sqli", h_blind_sqli)
    app.router.add_get("/vulnerable/c025_nosqli", h_nosqli)
    app.router.add_get("/vulnerable/c026_cmdi", h_cmdi)
    app.router.add_get("/vulnerable/c027_os_cmdi", h_os_cmdi)
    app.router.add_get("/vulnerable/c028_ssti", h_ssti)
    app.router.add_get("/vulnerable/c029_header_inj", h_header_injection)
    app.router.add_get("/vulnerable/c030_crlf", h_crlf_injection)
    app.router.add_get("/vulnerable/c031_traversal", h_path_traversal)
    app.router.add_get("/vulnerable/c032_lfi", h_lfi)
    app.router.add_post("/vulnerable/c033_xxe", h_xxe)
    app.router.add_get("/vulnerable/c034_ldap", h_ldap)
    app.router.add_get("/vulnerable/c035_el", h_el_injection)
    app.router.add_get("/vulnerable/c036_ssrf", h_ssrf_proxy)
    app.router.add_get("/robots.txt", lambda r: web.Response(text="User-agent: *\nDisallow: /admin\nDisallow: /secret\n"))

    # Category D: XSS
    app.router.add_get("/vulnerable/c037_xss", h_reflected_xss)
    app.router.add_get("/vulnerable/c038_stored_xss", h_reflected_xss)
    app.router.add_get("/vulnerable/c039_dom_xss", h_dom_xss)
    app.router.add_get("/vulnerable/c040_html_inj", h_reflected_xss)
    app.router.add_get("/vulnerable/c041_attr_xss", h_reflected_xss)
    app.router.add_get("/vulnerable/c042_js_xss", h_reflected_xss)
    app.router.add_get("/vulnerable/c043_url_xss", h_reflected_xss)
    app.router.add_get("/vulnerable/c044_mxss", h_reflected_xss)
    app.router.add_get("/vulnerable/c045_filter_bypass", h_reflected_xss)
    app.router.add_get("/vulnerable/c046_unsafe_render", h_reflected_xss)

    # Category E: Misconfig
    app.router.add_get("/vulnerable/c047_missing_csp", h_missing_security_headers)
    app.router.add_get("/vulnerable/c048_weak_csp", lambda r: web.Response(text="Weak CSP", headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}))
    app.router.add_get("/vulnerable/c049_clickjacking", h_clickjacking)
    app.router.add_get("/vulnerable/c050_mime", h_missing_security_headers)
    app.router.add_get("/crossdomain.xml", lambda r: web.Response(text='<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>', content_type="application/xml"))
    app.router.add_route("*", "/vulnerable/c052_methods", h_insecure_methods)
    app.router.add_get("/install.php", lambda r: web.Response(text="Setup Wizard - Step 1: Install Database", status=200))
    app.router.add_get("/vulnerable/c054_error", lambda r: web.Response(text="500 Internal Error: Traceback (most recent call last):\n  File '/app/views.py', line 42", status=500))
    app.router.add_post("/upload", h_file_upload)
    app.router.add_post("/api/upload", h_file_upload)
    app.router.add_post("/vulnerable/c055_upload", h_file_upload)
    app.router.add_get("//admin", lambda r: web.Response(text="Admin panel bypass via double slash", status=200))

    # Category F: Sensitive Data
    app.router.add_get("/vulnerable/c057_keys", h_exposed_keys)
    app.router.add_get("/main.js.map", h_source_map)
    app.router.add_get("/vulnerable/c059_pii", lambda r: web.Response(text=f"Token query: {r.query.get('token', '')}"))
    app.router.add_get("/vulnerable/c060_comment", lambda r: web.Response(text="<html><!-- TODO: remove db_pass=synthetic_secret_123 --></html>", content_type="text/html"))
    app.router.add_get("/index.php.bak", lambda r: web.Response(text="<?php // Backup copy with DB_PASS=synthetic_123 ?>", status=200))
    app.router.add_get("/backup.sql", lambda r: web.Response(text="CREATE TABLE users (id INT, password VARCHAR(255));\nINSERT INTO users VALUES (1, 'hash');\n", status=200))
    app.router.add_get("/vulnerable/c063_bucket", lambda r: web.Response(text="<ListBucketResult><Name>my-bucket</Name><Contents><Key>secret.pdf</Key></Contents></ListBucketResult>", content_type="application/xml"))
    app.router.add_get("/.git/HEAD", h_git_head)
    app.router.add_get("/vulnerable/c065_unencrypted", lambda r: web.Response(text='<form action="http://app.target.com/login" method="POST"><input type="password"></form>', content_type="text/html"))
    app.router.add_get("/vulnerable/c066_storage", lambda r: web.Response(text="<script>localStorage.setItem('auth_token', 'synthetic_token_123');</script>", content_type="text/html"))

    # Category G: Business Logic & Access Control
    app.router.add_get("/vulnerable/c067_idor", h_idor_numeric)
    app.router.add_get("/vulnerable/c068_idor_uuid", lambda r: web.Response(text=json.dumps(users_db["user_b"]), content_type="application/json", status=200))
    app.router.add_get("/api/v1/accounts/1002", lambda r: web.Response(text=json.dumps(users_db["user_b"]), content_type="application/json", status=200))
    app.router.add_post("/vulnerable/c070_mass_assignment", h_mass_assignment)
    app.router.add_get("/api/admin/users", lambda r: web.Response(text=json.dumps(list(users_db.values())), content_type="application/json", status=200))
    app.router.add_post("/api/user/delete", lambda r: web.Response(text=json.dumps({"status": "deleted", "id": 1002}), content_type="application/json", status=200))
    app.router.add_post("/vulnerable/c073_price", lambda r: web.Response(text=json.dumps({"status": "order_placed", "charged": r.query.get("price", "0.01")}), content_type="application/json", status=200))
    app.router.add_post("/checkout/step3", lambda r: web.Response(text=json.dumps({"status": "checkout_completed", "step": 3}), content_type="application/json", status=200))
    app.router.add_post("/vulnerable/c075_race_condition", h_race_condition)
    app.router.add_post("/vulnerable/c076_replay", lambda r: web.Response(text=json.dumps({"success": True, "tx_id": "tx_9999"}), content_type="application/json", status=200))
    app.router.add_post("/vulnerable/c077_reauth", lambda r: web.Response(text=json.dumps({"status": "email_updated", "new_email": "attacker@corp.internal"}), content_type="application/json", status=200))

    # Negative Control (Secure Application Baseline)
    app.router.add_get("/secure/app", h_secure_application)

    # Deceptive & False-Positive Controls
    app.router.add_get("/deceptive/sqli_500", h_deceptive_sqli_500)
    app.router.add_get("/deceptive/xss_encoded", h_deceptive_xss_encoded)
    app.router.add_get("/deceptive/soft_404", h_deceptive_soft_404)
    app.router.add_get("/admin", h_deceptive_admin_login)
    app.router.add_get("/deceptive/products", h_deceptive_public_products)

    # Recon & Asset Intelligence Endpoints
    async def h_portal_page(request: web.Request) -> web.Response:
        return web.Response(
            text="""<!DOCTYPE html>
<html>
<head>
  <title>Corporate Portal & API Gateway</title>
  <meta name="generator" content="WordPress 6.2">
  <script src="/static/app.js"></script>
</head>
<body>
  <h1>Welcome to Corporate Portal</h1>
  <a href="/api/v1/accounts/1002">View Account</a>
  <a href="/vulnerable/c003_env">System Config</a>
  <form action="/upload" method="POST" enctype="multipart/form-data">
    <input type="file" name="doc_upload">
    <input type="submit" value="Upload">
  </form>
  <form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign In</button>
  </form>
</body>
</html>""",
            content_type="text/html",
            headers={"Server": "nginx/1.22.1", "X-Powered-By": "PHP/8.1.0"},
            status=200,
        )

    async def h_app_js(request: web.Request) -> web.Response:
        return web.Response(
            text="""
            console.log("Portal Initialized");
            function loadData() {
                fetch("/api/v1/accounts/1002").then(r => r.json());
                fetch("/api/v2/orders").then(r => r.json());
                fetch("/graphql").then(r => r.json());
            }
            """,
            content_type="application/javascript",
            status=200,
        )

    async def h_sitemap_xml(request: web.Request) -> web.Response:
        return web.Response(
            text="""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/app_index</loc></url>
  <url><loc>/api/v1/accounts/1002</loc></url>
  <url><loc>/secure/app</loc></url>
</urlset>""",
            content_type="application/xml",
            status=200,
        )

    async def h_openapi_json(request: web.Request) -> web.Response:
        return web.Response(
            text=json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "Corporate API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/accounts/{id}": {
                        "get": {"summary": "Get account", "parameters": [{"name": "id", "in": "path"}]}
                    },
                    "/api/upload": {
                        "post": {"summary": "Upload file"}
                    }
                }
            }),
            content_type="application/json",
            status=200,
        )

    async def h_redirect_external(request: web.Request) -> web.Response:
        return web.Response(
            status=302,
            headers={"Location": "http://unauthorized-victim.local/api/secret"},
        )

    async def h_redirect_chain_1(request: web.Request) -> web.Response:
        return web.Response(
            status=302,
            headers={"Location": "/redirect/chain_2"},
        )

    async def h_redirect_chain_2(request: web.Request) -> web.Response:
        return web.Response(
            status=302,
            headers={"Location": "/app_index"},
        )

    async def h_rate_limited(request: web.Request) -> web.Response:
        return web.Response(
            status=429,
            text="Too Many Requests",
            headers={"Retry-After": "60"},
        )

    app.router.add_get("/app_index", h_portal_page)
    app.router.add_get("/static/app.js", h_app_js)
    app.router.add_get("/sitemap.xml", h_sitemap_xml)
    app.router.add_get("/openapi.json", h_openapi_json)
    app.router.add_get("/redirect/external", h_redirect_external)
    app.router.add_get("/redirect/chain_1", h_redirect_chain_1)
    app.router.add_get("/redirect/chain_2", h_redirect_chain_2)
    app.router.add_get("/rate_limited", h_rate_limited)

    # Phase 5 Parameter-Rich & Negative Control Endpoints
    async def h_param_json_user_profile(request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.Response(status=400, text='{"error":"invalid_json"}', content_type="application/json")
        uid = data.get("user_id", 1)
        uname = data.get("username", "guest")
        return web.Response(
            text=f'{{"status":"ok","user_id":{json.dumps(uid)},"username":{json.dumps(uname)}}}',
            content_type="application/json",
        )

    async def h_param_search_dynamic(request: web.Request) -> web.Response:
        q = request.query.get("q", "")
        return web.Response(
            text=f"<html><body><h1>Search Results</h1><p>You searched for: {q}</p></body></html>",
            content_type="text/html",
        )

    async def h_param_search_safe_escape(request: web.Request) -> web.Response:
        import html
        q = request.query.get("q", "")
        escaped_q = html.escape(q)
        return web.Response(
            text=f"<html><body><h1>Search Results</h1><p>You searched for: {escaped_q}</p></body></html>",
            content_type="text/html",
        )

    async def h_param_calc_dynamic(request: web.Request) -> web.Response:
        expr = request.query.get("expr", "")
        # Safe deterministic evaluation of arithmetic canaries: $(( n1 * n2 )) or {{n1*n2}}
        m = re.search(r"\$\(\(\s*(\d+)\s*\*\s*(\d+)\s*\)\)|{{\s*(\d+)\s*\*\s*(\d+)\s*}}", expr)
        if m:
            n1 = int(m.group(1) or m.group(3))
            n2 = int(m.group(2) or m.group(4))
            return web.Response(text=f"<html><body>Result: {n1 * n2}</body></html>", content_type="text/html")
        return web.Response(text=f"<html><body>Input: {expr}</body></html>", content_type="text/html")

    async def h_param_calc_static(request: web.Request) -> web.Response:
        expr = request.query.get("expr", "")
        return web.Response(text=f"<html><body>Static Output: static_literal</body></html>", content_type="text/html")

    async def h_param_sql_syntax_error(request: web.Request) -> web.Response:
        id_param = request.query.get("id", "1")
        if "'" in id_param:
            return web.Response(
                status=500,
                text="Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                content_type="text/plain",
            )
        return web.Response(text=f'{{"account_id": {id_param}, "balance": 500}}', content_type="application/json")

    async def h_param_generic_error_500(request: web.Request) -> web.Response:
        param = request.query.get("val", "")
        if param == "trigger_error":
            return web.Response(status=500, text="Internal Server Error: Unexpected application fault", content_type="text/plain")
        return web.Response(text="Normal OK Response", content_type="text/plain")

    app.router.add_post("/api/v1/user_profile", h_param_json_user_profile)
    app.router.add_get("/search_dynamic", h_param_search_dynamic)
    app.router.add_get("/search_safe_escape", h_param_search_safe_escape)
    app.router.add_get("/calc_dynamic", h_param_calc_dynamic)
    app.router.add_get("/calc_static", h_param_calc_static)
    app.router.add_get("/sql_syntax_error", h_param_sql_syntax_error)
    app.router.add_get("/generic_error_500", h_param_generic_error_500)

    return app
