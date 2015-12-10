#!/usr/bin/env python


import select
import socket
import sys
import json

from Message import ListResponseMessage
from Message import LoginResponseMessage
from Message import SelectUserResponseMessage

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


class Server:
  def __init__(self): 
    self.host = ''
    self.port = 50010

    self.size = 1024
    self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serverSocket.bind((self.host, self.port))
    self.serverSocket.listen(5)
    self.selectList = [self.serverSocket, sys.stdin]
    self.running = 1

    self.usersOnline = {} # { user1:(port, pub_key) , user2:(port, pub_key) }

    self.users = {
      'kevin': '123',
      'bob': 'enter'
    }

    self.debugMode = True

    self.run()


  def run(self):
    print "Chat server started."
    while self.running:
      inputready,outputready,exceptready = select.select(self.selectList,[],[])
      for s in inputready:
        # handle own socket
        if s == self.serverSocket:
          client, address = self.serverSocket.accept()
          self.selectList.append(client)
        # handle user input
        elif s == sys.stdin:
          junk = sys.stdin.readline()
          self.running = 0
        # handle message from client
        else:
          self.debug("receiving incoming message")
          data_encrypted = s.recv(self.size)
          data_decrypted =  self.decrypt("MY_PRIVATE_KEY", data_encrypted)
          if len(data_decrypted) > 0:
            self.handleMessageType(s, json.loads(data_decrypted))

          # client closed connection
          else:
            s.close()
            self.selectList.remove(s)

    self.serverSocket.close()

  # =============================================================================================
  # Enables debug messages
  def debug(self, text):
    if self.debugMode:
      print "[DEBUG] " + text

  # =============================================================================================
  def handleMessageType(self, clientSocket, jsonMessage):
    if jsonMessage['messageType'] == 'serverMessage':
      print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']
      clientSocket.send(json.dumps(jsonMessage))

    if jsonMessage['messageType'] == 'login':
      if jsonMessage['username'] in self.users and jsonMessage['password'] == self.users[jsonMessage['username']]:
        self.usersOnline[jsonMessage['username']] = (jsonMessage['srcPort'], jsonMessage['clientPublicKey'])
        self.debug("usersOnline " + str(self.usersOnline))

        loginResponseMessage = LoginResponseMessage(jsonMessage['username'], 'success')
        clientSocket.send(loginResponseMessage.encode())

      else:
        loginResponseMessage = LoginResponseMessage(jsonMessage['username'], 'fail')
        clientSocket.send(loginResponseMessage.encode())

    if jsonMessage['messageType'] == 'list':
      listMessage = ListResponseMessage(self.usersOnline.keys())
      clientSocket.send(listMessage.encode())

    if jsonMessage['messageType'] == 'selectUser':
      self.debug("selecting user")
      user = jsonMessage['username']
      destinationPort = ''
      if user in self.usersOnline:
        destinationPort = self.usersOnline[user][0]
        self.debug("selected user " + str(user) + " " + str(destinationPort))

      selectUserResponse = SelectUserResponseMessage(
        destinationPort, user, "SESSION_KEY", "NONCE", "TIMESTAMP", "ENCRYPTED_FORWARD_BLOCK")
      clientSocket.send(self.encrypt("USERID1_PUBLIC_KEY", selectUserResponse.encode()))


  # =============================================================================================
  def encrypt(self, public_key, data):
    self.debug("encrypting data...")

    # hash_length = 16                   # length of cryptographic hash in bytes
    # symkey = os.urandom(hash_length)   # generate a random symmetric key
    # iv = os.urandom(hash_length)       # generate an initialization vector

    # # Pad the data then encrypt using 128-bit AES-CBC
    # data_padded = self.enpad(data, hash_length)
    # cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
    # encryptor = cipher.encryptor()
    # data_encrypted = encryptor.update(data_padded) + encryptor.finalize()

    # # Encrypt the symmetric key using the public key
    # symkey_encrypted = public_key.encrypt(symkey + iv, padding.OAEP(
    #   mgf=padding.MGF1(algorithm=hashes.SHA1()),
    #   algorithm=hashes.SHA1(),
    #   label=None)
    # )

    # # Append encrypted symmetric key to the encrypted data
    # ciphertext = symkey_encrypted + data_encrypted

    # # # Sign the data and append signature to ciphertext
    # # signature = self.signature_sign(ciphertext, private_key)
    # # ciphertext_signed = signature + ciphertext

    
    self.debug("contents successfully encrypted.")

    return data

    # return ciphertext



    # print "\n----------------------------------------------"
    # print "[SELF-TEST]"

    # with open("cs4740_key2.pem", "rb") as key_file:
    #     test_private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    # with open("cs4740_key1.pub", "rb") as key_file:
    #     test_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    # self.decrypt(self.fileoutput_buffer, test_private_key, test_public_key)


  def decrypt(self, private_key, ciphertext):
    self.debug("decrypting message...")

    # # Decompose the signed ciphertext into its respective parts
    # # signature = ciphertext_signed[:256]
    # # ciphertext = ciphertext_signed[256:]
    # symkey_encrypted = ciphertext[:256]
    # message_encrypted = ciphertext[256:]

    # # Validate the signature
    # # self.signature_validate(signature, ciphertext, public_key)

    # # Decrypt the symmetric key using the private key
    # symkey_decrypted = private_key.decrypt(
    #   symkey_encrypted, 
    #   padding.OAEP(
    #     mgf=padding.MGF1(algorithm=hashes.SHA1()),
    #     algorithm=hashes.SHA1(),
    #     label=None
    #     )
    #   )

    # # Separate the encrypted symmetric key from the encrypted data
    # symkey = symkey_decrypted[:16]
    # iv = symkey_decrypted[16:]

    # # Decrypt the data then remove padding
    # cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
    # decryptor = cipher.decryptor()
    # data_padded = decryptor.update(data_encrypted) + decryptor.finalize()
    # data = self.depad(data_padded)

    self.debug("decryption complete.")

    return ciphertext

    # return data

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



# Start server
Server() 