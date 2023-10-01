from flask import Flask, request, jsonify
from dilithium.dilithium import Dilithium2
import base64
from flask_cors import CORS
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt

app = Flask(__name__)
CORS(app)

eth_k = generate_eth_key()
sk_hex = eth_k.to_hex()
pk_hex = eth_k.public_key.to_hex()

@app.route('/', methods=['GET'])
def home():
    return jsonify(message="Welcome to the Password Manager App")


#Generate random key pair for the user
@app.route('/generate', methods=['POST'])
def generate():
    pk, sk = Dilithium2.keygen()
    pk = encrypt(pk_hex, pk)
    sk = encrypt(pk_hex, sk)
    # print(encrypt_message(base64.b64encode(sk).decode()))
    return jsonify(sk=base64.b64encode(sk).decode(), pk=base64.b64encode(pk).decode())

@app.route('/sign_message', methods=['POST'])
def sign_message():
    data = request.get_json()
    message = data.get('message')
    sk = data.get('sk')
    
    sk = base64.b64decode(sk)
    print("message: ", message)
    message = bytes(message,"ascii")
    sk = decrypt(sk_hex, sk)
    print("KD Private key " , sk , '\n')
    signature = Dilithium2.sign(sk, message)
    return jsonify(signed=base64.b64encode(signature).decode())

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    data = request.get_json()
    message = data.get('message')
    pk = data.get('pk')
    signed = data.get('signed')
    
    pk = base64.b64decode(pk)
    pk = decrypt(sk_hex, pk)
    message = bytes(message,"ascii")
    signed = base64.b64decode(signed)
    print("pk2: ", message)
    if (Dilithium2.verify(pk, message, signed)):
        return jsonify(message="Signature verified successfully")
    else:
        return jsonify(message="Signature verification failed, Try again...")


if __name__ == '__main__':
    app.run(debug=True)
