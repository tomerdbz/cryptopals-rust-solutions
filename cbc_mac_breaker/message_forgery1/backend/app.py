from flask import Flask, request, make_response
from Crypto.Cipher import AES
from base64 import b64decode
from Crypto.Util.Padding import pad

key = b'YELLOW SUBMARINE'

app = Flask(__name__)


@app.route('/test')
def is_verified():
    print("****************")
    iv = b64decode(request.args.get('iv'))
    print(f'iv: {iv}')
    message = b64decode(request.args.get('message'))
    print(f'message: {message}')
    print(f'mac: {b64decode(request.args.get("mac"))}')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    mac = ciphertext[-AES.block_size:]
    print(f"our mac result: {mac}")

    if mac != b64decode(request.args.get('mac')):
        return make_response("", 404)

    print(f'{message} was authorized..\n\n')
    return make_response("", 200)
