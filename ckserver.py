#!/usr/bin/env python


import select
import socket
import sys
import json
import time

from Message import ListResponseMessage
from Message import LoginResponseMessage
from Message import SelectUserResponseMessage
from Message import NeedhamSchroeder_Auth3

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

import binascii


class Server:
  def __init__(self): 
    self.host = ''
    self.port = 50011

    self.size = 1024
    self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serverSocket.bind((self.host, self.port))
    self.serverSocket.listen(5)
    self.selectList = [self.serverSocket, sys.stdin]
    self.running = 1

    self.usersOnline = {} # { user1:(port, pub_key) , user2:(port, pub_key) }

    self.users = {
      'chris': '123',
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
          # data_decrypted =  self.decrypt("MY_PRIVATE_KEY", data_encrypted)
          data_decrypted = data_encrypted
          if len(data_decrypted) > 0:
            self.handleMessageType(s, json.loads(data_decrypted))

          # client closed connection
          else:
            s.close()
            self.selectList.remove(s)

    self.serverSocket.close()

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
  def handleMessageType(self, clientSocket, jsonMessage):
    # if jsonMessage['messageType'] == 'serverMessage':
    #   print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']
    #   destPubKey = "".join([str(e) for e in self.usersOnline[jsonMessage['username']][1]])
    #   clientSocket.send(self.encrypt(json.dumps(jsonMessage)))

    if jsonMessage['messageType'] == 'login':
      username = jsonMessage['username']
      password = jsonMessage['password']
      loginResponseMessage = None
      if username in self.users and password == self.users[username]:
        self.usersOnline[username] = (jsonMessage['srcPort'], jsonMessage['clientPublicKey'])
        loginResponseMessage = LoginResponseMessage(username, 'success')
      else:
        loginResponseMessage = LoginResponseMessage(username, 'fail')
      destPubKey = "".join([str(e) for e in self.usersOnline[username][1]])
      clientSocket.send(self.encrypt(destPubKey, loginResponseMessage.encode()))

    if jsonMessage['messageType'] == 'list':
      listMessage = ListResponseMessage(self.usersOnline.keys())
      destPubKey = "".join([str(e) for e in self.usersOnline[jsonMessage['username']][1]])
      clientSocket.send(self.encrypt(destPubKey, listMessage.encode()))

    if jsonMessage['messageType'] == 'selectUser':
      self.debug("selecting user")
      usernameOrigin = jsonMessage['usernameOrigin']
      usernameRequested = jsonMessage['usernameRequested']
      nonceReceived = jsonMessage['nonce']
      destinationPort = None
      if usernameRequested in self.usersOnline:
        destinationPort = self.usersOnline[usernameRequested][0]
        self.debug("selected user " + str(usernameRequested) + " " + str(destinationPort))

      nsblock_auth3_raw = NeedhamSchroeder_Auth3("USER2_USERNAME", "SESSION_KEY_FROM_SERVER", "TIMESTAMP_FROM_SERVER")
      nsblock_auth3 = nsblock_auth3_raw.encode()
      # destPubKeyRequested = "".join([str(e) for e in self.usersOnline[usernameRequested][1]])
      # nsblock_auth3_encrypted_hex = str(binascii.hexlify(self.encrypt(destPubKeyRequested, nsblock_auth3)))

      selectUserResponse = SelectUserResponseMessage(
        destinationPort, usernameRequested, "SESSION_KEY", nonceReceived, self.genTime(), nsblock_auth3)
      destPubKeyOrigin = "".join([str(e) for e in self.usersOnline[usernameOrigin][1]])
      self.debug(selectUserResponse.encode)
      clientSocket.send(self.encrypt(destPubKeyOrigin, selectUserResponse.encode()))

      # messageType = "selectUserResponse"
      # sessionKey = "SESSION_KEY"
      # nonce = "NONCE"
      # timestamp = "TIMESTAMP"
      # # nsblock_auth3_encrypted = "ENCRYPTED_BLOCK"
      # selectUserResponse = '{"messageType": "' + messageType + '", "destinationPort": "' + str(destinationPort) + '", "destinationUsername": "' + str(usernameRequested) + '", "sessionKey": "' + str(sessionKey) + '", "nonceReturned": "' + str(nonce) + '", "timestamp": "' + str(timestamp) + '", "nsblock_auth3": "' + nsblock_auth3_encrypted + '"}'
      # destPubKeyOrigin = "".join([str(e) for e in self.usersOnline[usernameOrigin][1]])
      # clientSocket.send(self.encrypt(destPubKeyOrigin, selectUserResponse))

  # =============================================================================================
  def genTime(self):
    return time.time()

  def validateTimestamp(self, timestampExpected, timestampReceived):
    self.debug("validating timestamp")
    try:
      if abs(timestampExpected - timestampReceived) > 60:
        print "[ERROR] Timestamp validation failed."
        # self.end()
    except:
      print "[ERROR] Timestamp validation failed."
      # self.end()

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