import urllib.request
import yaml

url = 'https://raw.githubusercontent.com/juice-shop/juice-shop/master/data/static/challenges.yml'
data = yaml.safe_load(urllib.request.urlopen(url).read().decode('utf-8'))

with open('juice_shop_vulns.md', 'w') as f:
    f.write('| Vuln Type / Category | Challenge Name | OWASP Category |\n')
    f.write('|---|---|---|\n')
    for c in data:
        f.write(f"| {c.get('category', '')} | {c.get('name', '')} | {c.get('category', '')} |\n")
