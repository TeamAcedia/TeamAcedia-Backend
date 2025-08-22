import requests
from hashlib import sha256

BASE_URL = "http://localhost:22222"
REGISTER_ENDPOINT = "/api/register/"
LOGIN_ENDPOINT = "/api/login/"
VERIFY_ENDPOINT = "/api/verify-session/"
JOIN_ENDPOINT = "/api/server/join/"
LEAVE_ENDPOINT = "/api/server/leave/"
GET_PLAYERS_ENDPOINT = "/api/server/players/"

USERNAME = "testaccount"
PASSWORD = "1234"

def test_register():
	"""
	Registers a new user.
	"""
	payload = {
		"username": USERNAME,
		"password": sha256(PASSWORD.encode('utf-8')).hexdigest()
	}
	response = requests.post(BASE_URL + REGISTER_ENDPOINT, json=payload)
	print("Register Status Code:", response.status_code)
	print("Register Response:", response.text)

def test_login():
	"""
	Logs in with username and password and prints the session token.
	"""
	payload = {
		"username": USERNAME,
		"password": sha256(PASSWORD.encode('utf-8')).hexdigest()
	}
	response = requests.post(BASE_URL + LOGIN_ENDPOINT, json=payload)
	print("Login Status Code:", response.status_code)

	# Try to parse JSON response
	try:
		data = response.json()
		print("Login Response:", data)
		if "session_token" in data:
			print("Session Token:", data["session_token"], "\n")
			return data["session_token"]
	except Exception:
		print("Login Response (raw):", response.text)


def test_verify_session(session_token):
	"""
	Sends a JSON payload with the session token to the verify-session endpoint
	and prints the response.
	"""
	payload = {
		"token": session_token
	}
	response = requests.post(BASE_URL + VERIFY_ENDPOINT, json=payload)
	print("Verify Status Code:", response.status_code)
	
	# Try to parse JSON, fallback to plain text
	try:
		print("Response JSON:", response.json())
	except Exception:
		print("Response Text:", response.text)

def test_join_server(session_token):
    """
    Announces that the user joined a server.
    """
    payload = {
        "token": session_token,
        "joined_username": USERNAME,
        "server_address": "test.teamacedia.baselinux.net",
        "server_port": "30000"
    }
    response = requests.post(BASE_URL + JOIN_ENDPOINT, json=payload)
    print("Join Server Status Code:", response.status_code)
    print("Join Server Response:", response.text)

def test_get_server_players(session_token):
    """
    Retrieves all players currently joined to a server.
    """
    payload = {
        "token": session_token,
        "server_address": "test.teamacedia.baselinux.net",
        "server_port": "30000"
    }
    response = requests.post(BASE_URL + GET_PLAYERS_ENDPOINT, json=payload)
    print("Get Players Status Code:", response.status_code)
    
    try:
        print("Get Players Response JSON:", response.json())
    except Exception:
        print("Get Players Response Text:", response.text)

def test_leave_server(session_token):
    """
    Announces that the user left the server.
    """
    payload = {
        "token": session_token,
        "joined_username": USERNAME,
        "server_address": "test.teamacedia.baselinux.net",
        "server_port": "30000"
    }
    response = requests.post(BASE_URL + LEAVE_ENDPOINT, json=payload)
    print("Leave Server Status Code:", response.status_code)
    print("Leave Server Response:", response.text)

if __name__ == "__main__":
	# Optional: register the user first
	test_register()
	# Then login
	token = test_login()
	
	if token:
		# Join server
		test_join_server(token)
		# Get server players
		test_get_server_players(token)
		# Leave server
		test_leave_server(token)

