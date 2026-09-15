import urllib.parse
import json
from typing import Optional
from backend.services.request_engine import RequestSpec

def build_injected_request(candidate: dict, new_payload: str) -> Optional[RequestSpec]:
    affected_url = candidate.get("affected_url")
    affected_param = candidate.get("affected_param") or candidate.get("location")
    proof_request = candidate.get("proof_request", "")
    
    if not affected_url or not proof_request:
        return None
        
    # Parse proof_request to reconstruct the request details
    lines = proof_request.split("\n")
    if len(lines) == 1 and "\r\n" in proof_request:
        lines = proof_request.split("\r\n")
    
    if not lines or not lines[0]:
        return None
        
    req_line_parts = lines[0].strip().split(" ")
    if len(req_line_parts) < 2:
        return None
    method = req_line_parts[0].upper()
    
    headers = {}
    body = None
    i = 1
    while i < len(lines):
        line = lines[i].strip("\r\n")
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
        
    if i + 1 < len(lines):
        body_content = "\n".join(lines[i+1:]).strip("\r\n")
        if body_content:
            body = body_content
            
    parsed = urllib.parse.urlparse(affected_url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    # 1. Check if param is in query string
    if affected_param and affected_param in query_params:
        query_params[affected_param] = [new_payload]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        return RequestSpec(url=new_url, method=method, headers=headers, body=body)
        
    # 2. Check if param is in JSON body (by content type or just shape)
    content_type = headers.get("Content-Type", "").lower()
    if affected_param and body and ("application/json" in content_type or body.strip().startswith("{")):
        try:
            data = json.loads(body)
            if affected_param in data:
                try:
                    parsed_payload = json.loads(new_payload)
                except json.JSONDecodeError:
                    parsed_payload = new_payload
                data[affected_param] = parsed_payload
                
                new_headers = dict(headers)
                if "Content-Type" in new_headers and "application/json" not in new_headers["Content-Type"].lower():
                    new_headers["Content-Type"] = "application/json"
                elif "content-type" in new_headers and "application/json" not in new_headers["content-type"].lower():
                    new_headers["content-type"] = "application/json"
                
                return RequestSpec(url=affected_url, method=method, headers=new_headers, body=json.dumps(data))
        except json.JSONDecodeError:
            pass
            
    # 3. Check if param is in form body
    if affected_param and body and "application/x-www-form-urlencoded" in content_type:
        body_params = urllib.parse.parse_qs(body, keep_blank_values=True)
        if affected_param in body_params:
            body_params[affected_param] = [new_payload]
            new_body = urllib.parse.urlencode(body_params, doseq=True)
            return RequestSpec(url=affected_url, method=method, headers=headers, body=new_body)
            
    # 4. Check if param is a header
    if affected_param and (affected_param in headers or affected_param.lower() in [k.lower() for k in headers.keys()]):
        new_headers = dict(headers)
        # Find exact case
        target_key = next((k for k in new_headers.keys() if k.lower() == affected_param.lower()), affected_param)
        new_headers[target_key] = new_payload
        return RequestSpec(url=affected_url, method=method, headers=new_headers, body=body)
    # 5. Fallback: return the un-injected base request
    return RequestSpec(url=affected_url, method=method, headers=headers, body=body)
