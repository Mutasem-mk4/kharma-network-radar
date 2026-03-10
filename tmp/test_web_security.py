import requests
import sys

BASE_URL = "http://127.0.0.1:8085"
ENDPOINTS = [
    "/api/status",
    "/api/radar",
    "/api/report/export",
    "/api/history",
    "/api/settings"
]

def test_unauthenticated():
    print("--- Testing Unauthenticated Access ---")
    for ep in ENDPOINTS:
        try:
            resp = requests.get(f"{BASE_URL}{ep}", timeout=2)
            print(f"GET {ep}: {resp.status_code} (Expected 401/302)")
        except Exception as e:
            print(f"GET {ep}: Failed to connect ({e})")

def test_health():
    print("\n--- Testing Public Health Endpoint ---")
    try:
        resp = requests.get(f"{BASE_URL}/api/health", timeout=2)
        print(f"GET /api/health: {resp.status_code} {resp.json()}")
    except Exception as e:
        print(f"GET /api/health: Failed ({e})")

if __name__ == "__main__":
    # Note: This requires the server to be running.
    # Since I cannot easily run persistent background processes and interact 
    # with them via requests in this env without manual launch, 
    # this script is for the user or for me if I launch it.
    test_unauthenticated()
    test_health()
