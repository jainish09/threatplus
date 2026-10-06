import requests

for t in ['all', 'ip', 'url', 'domain', 'hash', 'cve']:
    r = requests.get(f"http://127.0.0.1:8080/api/ioc?iocType={t}&limit=2")
    data = r.json()
    total = data.get('total', 0)
    items = data.get('data', [])
    first_obs = items[0]['observable'][:30] if items else 'None'
    print(f"Type: {t:7} | Total: {total:5} | Sample: {first_obs}")
