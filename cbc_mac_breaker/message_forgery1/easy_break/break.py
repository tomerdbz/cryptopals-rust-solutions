import requests
import subprocess
import json
from base64 import b64decode, b64encode
# send a legit request from attacker account to attacker account moving 1M bucks
# attacker intercept changes iv to original_iv XOR original_first_block XOR new_first_block

# api-endpoint
URL = "http://localhost:55400/test"


def xor_block(first, second):
    return bytes(a ^ b for a, b in zip(first, second))


move_to_myself_message = b"from=1&to=1&amount=1000000"
move_from_victim_to_myself_message = b"from=2&to=1&amount=1000000"

frontend_params = subprocess.run(
    ['python', 'frontend/sample_client.py', move_to_myself_message], capture_output=True).stdout

params = json.loads(frontend_params)

iv = b64decode(params['iv'])
print(f"original_iv = {params['iv']}")
# b"from=2&to=1&amoun"
move_from_victim_to_myself_first_block = move_from_victim_to_myself_message[:16]
# b"from=1&to=1&amoun"
original_move_from_victim_to_myself_first_block = move_to_myself_message[:16]

malicious_iv = xor_block(xor_block(iv, original_move_from_victim_to_myself_first_block),
                         move_from_victim_to_myself_first_block)

params['iv'] = b64encode(malicious_iv).decode()
params['message'] = b64encode(move_from_victim_to_myself_message).decode()
print(f"new_iv = { params['iv'] }")
# sending get request and saving the response as response object
r = requests.get(url=URL, params=params)
