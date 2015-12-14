from Message import ServerMessage
import os
import base64
import json
import binascii
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption
import re



class Sample():

    def __init__(self):
        self.debugMode = True
        self.message = "happy birthday to you"
        self.generateClientKeyPair()

        encMsg = self.encrypt(self.withKey(self.clientPublicKey), self.message)
        encMsg = binascii.b2a_base64(encMsg)

        serverMessage = ServerMessage(1234, encMsg)

        #finished = serverMessage.encode()
        finished = serverMessage.encode()

        msgOverWire = self.encrypt(self.withKey(self.clientPublicKey), finished)

        decrypt = self.decrypt(self.withKey(self.clientPrivateKey), msgOverWire)


        #start = 'message:'
        #end = ','

        #print s[s.find(start)+len(start):s.rfind(end)]

        #result = re.search('%s(.*)%s' % (start, end), decrypt).group(1)
        #print(decrypt)

        decryptJson = json.loads(decrypt)

        decryptMsgRaw = decryptJson['message']
        decryptMsgRaw = binascii.a2b_base64(encMsg)


        decryptMsg = self.decrypt(self.withKey(self.clientPrivateKey), decryptMsgRaw)
        print decryptMsg


        #bday = self.decrypt(self.withKey(self.clientPrivateKey), decrypt)



    def generateClientKeyPair(self):
        privateKey = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048,
          backend=default_backend()
        )

        serializedPub = privateKey.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        serializedPriv = privateKey.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        
        self.clientPrivateKey = serializedPriv
        self.clientPublicKey = serializedPub

    def encrypt(self, public_key_unserialized, data):
        self.debug("encrypting data...")

        public_key = self.serialize_key(public_key_unserialized, "public")

        hash_length = 16                   # length of cryptographic hash in bytes
        symkey = os.urandom(hash_length)   # generate a random symmetric key
        iv = os.urandom(hash_length)       # generate an initialization vector

        # Pad the data then encrypt using 128-bit AES-CBC
        data_padded = self.enpad(data, hash_length)
        cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data_encrypted = encryptor.update(data_padded) + encryptor.finalize()

        # Encrypt the symmetric key using the public key
        symkey_encrypted = public_key.encrypt(symkey + iv, padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA1()),
          algorithm=hashes.SHA1(),
          label=None)
        )

        # Append encrypted symmetric key to the encrypted data
        ciphertext = symkey_encrypted + data_encrypted

        # # Sign the data and append signature to ciphertext
        # signature = self.signature_sign(ciphertext, private_key)
        # ciphertext_signed = signature + ciphertext
        
        self.debug("contents successfully encrypted.")

        return ciphertext

    def decrypt(self, private_key_unserialized, ciphertext):
        self.debug("decrypting data...")

        private_key = self.serialize_key(private_key_unserialized, "private")

        # Decompose the signed ciphertext into its respective parts
        # signature = ciphertext_signed[:256]
        # ciphertext = ciphertext_signed[256:]
        symkey_encrypted = ciphertext[:256]
        data_encrypted = ciphertext[256:]

        # Validate the signature
        # self.signature_validate(signature, ciphertext, public_key)

        # Decrypt the symmetric key using the private key
        symkey_decrypted = private_key.decrypt(
          symkey_encrypted, 
          padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
            )
          )

        # Separate the encrypted symmetric key from the encrypted data
        symkey = symkey_decrypted[:16]
        iv = symkey_decrypted[16:]

        # Decrypt the data then remove padding
        cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data_padded = decryptor.update(data_encrypted) + decryptor.finalize()
        data = self.depad(data_padded)

        self.debug("decryption complete.")

        return data

    # Enables debug messages
    def debug(self, text):
        if self.debugMode:
            print "[DEBUG] " + text

    # Serializes the public/private keys
    def serialize_key(self, key_unserialized, key_type):
        key_serialized = None
        if key_type == "private":
          key_serialized = serialization.load_pem_private_key(
            key_unserialized, password=None, backend=default_backend()
            )
        elif key_type == "public":
          key_serialized = serialization.load_pem_public_key(
            key_unserialized, backend=default_backend()
            )   
        return key_serialized

    def enpad(self, message, hash_length):
      pad_size = hash_length - len(message) % hash_length
      padding = pad_size * chr(pad_size)
      return message + padding

    # Removes padding from a message
    def depad(self, message):
      univalue = ord(message[-1])
      return message[0:-univalue]

    def withKey(self, unjoined):
        return "".join([str(e) for e in unjoined])

Sample()