#!/usr/bin/env python
import sys

import os
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


# Christophe Leung
# Simple Encrypt-Decrypt
# December 10, 2015
# =================================================================================================
class encryptDecrypt():
    def __init__(self, fileinput):
        self.debugMode = True
        self.fileinput_path = fileinput
        self.clientPublicKey = None
        self.clientPrivateKey = None

    def run(self):
        self.clientPublicKey = self.file_read("array", self.fileinput_path)
        self.clientPrivateKey = self.file_read("array", "..\cs4740_key1.pem")
        clientPublicKey = "".join(self.clientPublicKey)
        clientPrivateKey = "".join(self.clientPrivateKey)
        ciphertext = self.encrypt(clientPublicKey, "hello world!")
        self.decrypt(clientPrivateKey, ciphertext)

    # =============================================================================================
    # Opens and reads a file
    def file_read(self, storeType, filepath):
        fileinput_content = None
        with open(filepath) as f:
            if storeType is "array":
                fileinput_content = f.readlines()
            elif storeType is "string":
                fileinput_content = f.read()
        return fileinput_content

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

    # Enables debug messages
    def debug(self, text):
        if self.debugMode:
            print "[DEBUG] " + text

    # =============================================================================================
    # Ends the program
    def end(self):
        sys.exit()

    # =============================================================================================
    def encrypt(self, public_key_unserialized, data):
      self.debug("encrypting data...")
      self.debug("encryption public key is: \n" + str(public_key_unserialized))

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
      self.debug("decryption private key is: \n" + str(private_key_unserialized))

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
      self.debug(str(ciphertext))
      self.debug(str(data))

      return data


    # =============================================================================================
    # Adds padding to a message
    def enpad(self, message, hash_length):
        pad_size = hash_length - len(message) % hash_length
        padding = pad_size * chr(pad_size)
        return message + padding
  
    # Removes padding from a message
    def depad(self, message):
        univalue = ord(message[-1])
        return message[0:-univalue]


# =================================================================================================
# The main function
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 2:
        print "Incorrect arguments. Needs [filename]"
    else:
        filename = args[1]
        t = encryptDecrypt(filename)
        t.run()
        t.end()
