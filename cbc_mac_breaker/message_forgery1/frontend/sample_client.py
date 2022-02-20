#! /usr/bin/python
import requests
import json
import argparse
from Crypto.Cipher import AES
from base64 import b64encode
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

parser = argparse.ArgumentParser(description='Server frontend')
parser.add_argument('message', type=str,
                    help='message of type from=#{from_id}&to=#{to_id}&amount=#{amount}')

args = parser.parse_args()


# api-endpoint
URL = "http://localhost:55400/test"

key = b'YELLOW SUBMARINE'
iv = get_random_bytes(16)
message = str.encode(args.message)
# message = b"from=1&to=2&amount=500"

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message, AES.block_size))
mac = ciphertext[-AES.block_size:]

# defining a params dict for the parameters to be sent to the API
PARAMS = {'message': b64encode(message).decode(),
          'iv': b64encode(iv).decode(),
          'mac': b64encode(mac).decode()}

# sending get request and saving the response as response object
r = requests.get(url=URL, params=PARAMS)

print(json.dumps(PARAMS))
