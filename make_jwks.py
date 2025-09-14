# make_jwks.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64, json, hashlib

def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

pub = serialization.load_pem_public_key(open(".keys/public_key.pem", "rb").read())
n = b64u(pub.public_numbers().n.to_bytes((pub.public_numbers().n.bit_length()+7)//8, 'big'))
e = b64u(pub.public_numbers().e.to_bytes((pub.public_numbers().e.bit_length()+7)//8, 'big'))

# simple kid from sha256(n|e)
kid = hashlib.sha256((n+e).encode()).hexdigest()[:32]

jwks = {".keys":[{"kty":"RSA","use":"sig","alg":"RS384","kid":kid,"n":n,"e":e}]}
open(".keys/jwks.json", "w").write(json.dumps(jwks, indent=2))
print("kid:", kid)

# kid: 58dd50d7bfa6a7be5f188919a551624b