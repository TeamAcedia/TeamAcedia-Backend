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
GET_ALL_USERS_ENDPOINT = "/api/users/get_all/"
CREATE_REWARD_ENDPOINT = "/api/rewards/create/"
UPDATE_REWARD_ENDPOINT = "/api/rewards/update/"
DELETE_REWARD_ENDPOINT = "/api/rewards/delete/"
GET_ALL_REWARDS_ENDPOINT = "/api/rewards/get_all/"
REDEEM_REWARD_ENDPOINT = "/api/rewards/redeem/"

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

def test_get_all_users(session_token):
	"""
	Tests getting all users in the db.
	"""
	payload = {
		"token": session_token,
	}
	response = requests.post(BASE_URL + GET_ALL_USERS_ENDPOINT, json=payload)
	print("\n--- GetAllUsersHandler Test ---")
	print("Status Code:", response.status_code)
	try:
		print("Response JSON:", response.json())
	except Exception:
		print("Response Text:", response.text)

def test_create_reward_code(session_token, cosmetic_id="cape1"):
	"""
	Creates a reward code for a given cosmetic.
	"""
	payload = {
		"token": session_token,
		"cosmetic_id": cosmetic_id
	}
	response = requests.post(BASE_URL + CREATE_REWARD_ENDPOINT, json=payload)
	print("Create Reward Code Status Code:", response.status_code)
	try:
		data = response.json()
		print("Create Reward Code Response JSON:", data)
	except Exception:
		print("Create Reward Code Response Text:", response.text)

def test_get_all_reward_codes(session_token):
	"""
	Retrieves all reward codes (Developer-only).
	"""
	payload = {"token": session_token}
	response = requests.post(BASE_URL + GET_ALL_REWARDS_ENDPOINT, json=payload)
	print("Get All Reward Codes Status Code:", response.status_code)
	try:
		data = response.json()
		print("All Reward Codes:", data)
		return data
	except Exception:
		print("Get All Reward Codes Response Text:", response.text)
		return []

def test_update_reward_code(session_token, code_id, new_code_id, cosmetic_id, max_uses):
	"""
	Updates a reward code's properties.
	"""
	payload = {
		"token": session_token,
		"old_code_id": code_id,
		"new_code_id": new_code_id,
		"cosmetic_id": cosmetic_id,
		"max_uses": max_uses
	}

	response = requests.post(BASE_URL + UPDATE_REWARD_ENDPOINT, json=payload)
	print(f"Update Reward Code ({code_id}) Status Code:", response.status_code)
	try:
		print("Update Reward Code Response JSON:", response.json())
	except Exception:
		print("Update Reward Code Response Text:", response.text)

def test_redeem_reward_code(session_token, reward_code):
	"""
	Redeems a reward code for the user.
	"""
	payload = {
		"token": session_token,
		"reward_code": reward_code
	}
	response = requests.post(BASE_URL + REDEEM_REWARD_ENDPOINT, json=payload)
	print(f"Redeem Reward Code ({reward_code}) Status Code:", response.status_code)
	try:
		print("Redeem Reward Code Response JSON:", response.json())
	except Exception:
		print("Redeem Reward Code Response Text:", response.text)


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
		test_get_all_users(token)
		test_create_reward_code(token, cosmetic_id="bats")
		codes = test_get_all_reward_codes(token)

		if codes:
			first_code = codes[0]["CodeID"]
			test_update_reward_code(token, first_code, "TEST-TEST", "bats", 5)
			test_redeem_reward_code(token, first_code)