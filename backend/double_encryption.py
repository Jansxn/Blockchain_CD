from dilithium.dilithium import Dilithium2
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

def generate_keypair():
    #returns keys in usable format
    ecc_sk = ec.generate_private_key(ec.SECP256K1())
    ecc_pk = ecc_sk.public_key()
    
    cd_pk, cd_sk = Dilithium2.keygen()
    
    sk, pk = [ecc_sk, cd_sk], [ecc_pk, cd_pk]
    return pk, sk

def sign_message(message, sk):
    #returns signed message in usable format
    ecc_sk = sk[0]
    cd_sk = sk[1]
    
    message = bytes(message,"ascii")
    cd_signature = Dilithium2.sign(cd_sk, message)
    ecc_signature = ecc_sk.sign(message, ec.ECDSA(hashes.SHA256()))
    return [ecc_signature, cd_signature]

def verify_message(message, signature, pk):
    #returns boolean
    ecc_pk = pk[0]
    cd_pk = pk[1]
    ecc_signature = signature[0]
    cd_signature = signature[1]
    
    message = bytes(message,"ascii")
    cd_verify = Dilithium2.verify(cd_pk, message, cd_signature)
    
    ecc_pk_pem = ecc_pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    loaded_ecc_pk = load_pem_public_key(ecc_pk_pem)
    ecc_verify = False
    
    try:
        loaded_ecc_pk.verify(ecc_signature, message, ec.ECDSA(hashes.SHA256()))
        ecc_verify = True
    except Exception as e:
        ecc_verify = False
    
    return ecc_verify and cd_verify