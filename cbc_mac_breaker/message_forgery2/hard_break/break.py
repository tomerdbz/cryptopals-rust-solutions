import requests
import argparse
import subprocess
import json
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
# send a legit request from attacker account to attacker account moving 1M bucks
# attacker intercept changes iv to original_iv XOR original_first_block XOR new_first_block

parser = argparse.ArgumentParser(description='Server frontend')
parser.add_argument('message', type=str,
                    help='''base64 encoded sniffed message JSON: {message: <message>, mac: <mac>}''')

args = parser.parse_args()

sniffed_message_params = json.loads(b64decode(args.message))
print(sniffed_message_params)
sniffed_message_mac = b64decode(sniffed_message_params['mac'])
sniffed_message = b64decode(sniffed_message_params['message'])

# api-endpoint
URL = "http://localhost:55400/test"


def xor_block(first, second):
    return bytes(a ^ b for a, b in zip(first, second))


move_to_myself_legit_message = b"from=1&tx_list=(;1;100000000000)"

legit_message_mac = b64decode(json.loads(
    b64decode(
        subprocess.run(['python', 'frontend/sample_client.py',
                       b64encode(move_to_myself_legit_message)], capture_output=True).stdout
    ))['mac'])

payload = b'(;1:1000000)'
extension = xor_block(xor_block(pad(payload, AES.block_size),
                      sniffed_message_mac), legit_message_mac)

new_mac = b64decode(json.loads(b64decode(
    subprocess.run(['python', 'frontend/sample_client.py', b64encode(pad(
        move_to_myself_legit_message, AES.block_size) + extension).decode()], capture_output=True)
    .stdout))['mac'])


new_params = {'message': b64encode(pad(sniffed_message, AES.block_size) + pad(payload, AES.block_size)).decode(),
              'mac': b64encode(new_mac).decode()}

r = requests.get(url=URL, params=new_params)
