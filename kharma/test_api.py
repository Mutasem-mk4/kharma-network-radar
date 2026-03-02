import requests
import json

BASE_URL = "http://127.0.0.1:8085"

def test_api():
    try:
        # Test status
        r = requests.get(f"{BASE_URL}/api/status")
        print(f"Status: {r.status_code}, {r.json()}")
        
        # Test radar
        r = requests.get(f"{BASE_URL}/api/radar")
        print(f"Radar: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            if data['status'] == 'success':
                print(f"Found {len(data['data'])} connections")
                if len(data['data']) > 0:
                    print(f"First connection: {data['data'][0]['process_name']} (PID: {data['data'][0]['pid']})")
            else:
                print(f"Radar error: {data['message']}")
    except Exception as e:
        print(f"Error connecting to server: {e}")

if __name__ == "__main__":
    test_api()
