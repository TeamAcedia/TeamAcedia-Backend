import requests
from hashlib import sha256

BASE_URL = "http://localhost:22222"
REGISTER_ENDPOINT = "/api/register/"
LOGIN_ENDPOINT = "/api/login/"
VERIFY_ENDPOINT = "/api/verify-session/"
JOIN_ENDPOINT = "/api/server/join/"
LEAVE_ENDPOINT = "/api/server/leave/"
GET_PLAYERS_ENDPOINT = "/api/server/players/"
GET_CAPES_ENDPOINT = "/api/cosmetics/capes/"
GET_USER_CAPES_ENDPOINT = "/api/users/capes/"
SET_SELECTED_CAPE_ENDPOINT = "/api/users/capes/set_selected/"
GET_SELECTED_CAPE_ENDPOINT = "/api/users/capes/get_selected/"

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
	Sends a JSON payload with the session token to the verify-session endpoint.
	"""
	payload = {"token": session_token}
	response = requests.post(BASE_URL + VERIFY_ENDPOINT, json=payload)
	print("Verify Status Code:", response.status_code)
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

def test_get_capes(session_token):
	"""
	Retrieves the list of available capes.
	"""
	payload = {
		"token": session_token,
	}
	response = requests.post(BASE_URL + GET_CAPES_ENDPOINT, json=payload)
	print("Get Capes Status Code:", response.status_code)
	try:
		data = response.json()
		print("Get Capes Response JSON:", data)
		print(f"Total capes: {len(data)}")
	except Exception:
		print("Get Capes Response Text:", response.text)
		
def test_get_user_capes(session_token):
	"""
	Retrieves the list of allowed capes for the current user.
	"""
	payload = {
		"token": session_token,
	}
	response = requests.post(BASE_URL + GET_USER_CAPES_ENDPOINT, json=payload)
	print("Get User Capes Status Code:", response.status_code)
	try:
		data = response.json()
		print("Get User Capes Response JSON:", data)
		print(f"Total User capes: {len(data)}")
	except Exception:
		print("Get User Capes Response Text:", response.text)


def test_set_selected_cape(session_token, cape_id="cape1"):
	"""
	Tests setting a user's selected cape.
	"""
	payload = {
		"token": session_token,
		"cape": cape_id,
	}
	response = requests.post(BASE_URL + SET_SELECTED_CAPE_ENDPOINT, json=payload)
	print("Set Selected Cape Status Code:", response.status_code)

	try:
		data = response.json()
		print("Set Selected Cape Response JSON:", data)
	except Exception:
		print("Set Selected Cape Response Text:", response.text)


def test_get_selected_cape(session_token):
	"""
	Tests retrieving the currently selected cape for the user.
	"""
	payload = {
		"token": session_token,
	}
	response = requests.post(BASE_URL + GET_SELECTED_CAPE_ENDPOINT, json=payload)
	print("Get Selected Cape Status Code:", response.status_code)

	try:
		data = response.json()
		print("Get Selected Cape Response JSON:", data)
		if "cape" in data:
			print(f"Currently selected cape: {data['cape']}")
	except Exception:
		print("Get Selected Cape Response Text:", response.text)

if __name__ == "__main__":
	test_register()
	token = test_login()
	
	if token:
		test_join_server(token)
		test_get_server_players(token)
		test_leave_server(token)
		test_get_capes(token)
		test_get_user_capes(token)
		test_set_selected_cape(token, cape_id="bats")
		test_get_selected_cape(token)