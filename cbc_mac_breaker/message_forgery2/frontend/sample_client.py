#! /usr/bin/python
import requests
import json
import argparse
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

parser = argparse.ArgumentParser(description='Server frontend')
parser.add_argument('message', type=str,
                    help='''base64 message of type from=#{from_id}&tx_list=#{transactions}\n
                    transactions look like: (;to:amount)*''')

args = parser.parse_args()


# api-endpoint
URL = "http://localhost:55400/test"

IV = b'YELLOW mUBeARINe'
key = b'YELLOW SUBMARINE'
message = b64decode(args.message)

cipher = AES.new(key, AES.MODE_CBC, IV)
ciphertext = cipher.encrypt(pad(message, AES.block_size))
mac = ciphertext[-AES.block_size:]

# defining a params dict for the parameters to be sent to the API
PARAMS = {'message': b64encode(message).decode(),
          'mac': b64encode(mac).decode()}

# sending get request and saving the response as response object
r = requests.get(url=URL, params=PARAMS)

print(b64encode(str.encode(json.dumps(PARAMS))).decode())
