import requests
import json

try:
    r = requests.get('http://127.0.0.1:8085/api/radar')
    data = r.json()
    with open('trace.txt', 'w', encoding='utf-8') as f:
        f.write(data.get('trace', 'No trace found'))
except Exception as e:
    print(f"Error: {e}")
