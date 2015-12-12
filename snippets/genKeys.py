#!/usr/bin/env python

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption

def generateClientKeyPair():
    privateKey = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
    )

    serializedPub = privateKey.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    serializedPriv = privateKey.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    print serializedPub
    print serializedPriv

    x = []

    print serializedPub.split("\n")

generateClientKeyPair()

# server:

# # Load private key of server
#   def loadServerPrivateKey(self):
#     self.serverPrivateKey = self.file_read("array", "private_ckserver.pem")