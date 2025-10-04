import requests
from hashlib import sha256

BASE_URL = "http://localhost:22222"
REGISTER_ENDPOINT = "/api/register/"
LOGIN_ENDPOINT = "/api/login/"
GET_ALL_USERS_ENDPOINT = "/api/users/get_all/"

USERNAME = "devaccount"
PASSWORD = "devpassword"

def test_get_all_users():
    # Register developer user (ignore errors if already exists)
    payload = {
        "username": USERNAME,
        "password": sha256(PASSWORD.encode()).hexdigest()
    }
    try:
        requests.post(BASE_URL + REGISTER_ENDPOINT, json=payload)
    except Exception:
        pass

    # Login
    status, token = None, None
    try:
        response = requests.post(BASE_URL + LOGIN_ENDPOINT, json=payload)
        status = response.status_code
        data = response.json()
        if "session_token" in data:
            token = data["session_token"]
    except Exception as e:
        print("Login failed:", e)
        return

    if not token:
        print("Failed to get session token. Cannot test GetAllUsersHandler.")
        return

    # Call GetAllUsersHandler
    response = requests.post(BASE_URL + GET_ALL_USERS_ENDPOINT, json={"token": token})
    print("\n--- GetAllUsersHandler Test ---")
    print("Status Code:", response.status_code)
    try:
        print("Response JSON:", response.json())
    except Exception:
        print("Response Text:", response.text)

if __name__ == "__main__":
    test_get_all_users()
