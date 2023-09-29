import requests
requests.post("http://localhost:5000/signup", json={"username": "admin", "password": "114514"}, timeout=1)
resp = requests.post("http://localhost:5000/signin", json={"username": "admin", "password": "114514"}, timeout=1)
token = resp.json()["data"]["access_token"]
resp = requests.post("http://localhost:5000/checkin", json={"access_token": token})
