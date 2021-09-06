import random
import time
from flask import Flask, request, make_response
from hashlib import sha1

app = Flask(__name__)

BLOCK_SIZE = 64

secret_key = random.randbytes(BLOCK_SIZE)


def hmac_sha1(key, message):
    if len(key) > BLOCK_SIZE:
        key = sha1(key)

    if len(key) < BLOCK_SIZE:
        key = key + [0] * (BLOCK_SIZE - len(key))

    outer_key_pad = bytearray([b ^ 0x5C for b in key])
    inner_key_pad = bytearray([b ^ 0x36 for b in key])

    return sha1(
        outer_key_pad +
        sha1(inner_key_pad + message).digest()
    ).digest()


def insecure_compare(given_sig, calculated_sig):
    for i in range(0, len(given_sig)):
        if given_sig[i] != calculated_sig[i]:
            return False
        # print(given_sig[i])
        time.sleep(0.005)  # time.sleep(0.05)
    return True


@ app.route('/test')
def is_verified():
    file_blob = request.args.get('file').encode()
    hmac = request.args.get('signature')
    are_equal = insecure_compare(
        bytes.fromhex(hmac), hmac_sha1(secret_key, file_blob))

    print(hmac_sha1(secret_key, file_blob).hex())

    if are_equal:
        return make_response("", 200)
    else:
        return make_response("", 500)
