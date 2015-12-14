#!/usr/bin/env python


import select
import socket
import sys
import json
import time

from Message import LoginAuthResponse
from Message import ListResponseMessage
from Message import LoginResponseMessage
from Message import SelectUserResponseMessage
from Message import NeedhamSchroeder_Auth3

import os
import base64
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


class Server:
  def __init__(self): 
    self.host = ''
    self.port = 50025

    self.size = 10000
    self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serverSocket.bind((self.host, self.port))
    self.serverSocket.listen(5)
    self.selectList = [self.serverSocket, sys.stdin]
    self.running = 1

    self.usersOnline = {} # { user1:(port, pub_key) , user2:(port, pub_key) }

    self.users = {
      'chris': '123',
      'kevin': '123',
      'bob': 'enter',
      'a': 'a',
      'b': 'b'
    }

    self.debugMode = False

    self.run()


  def run(self):
    print "Chat server started."

    self.loadServerPrivateKey()

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
          if len(data_encrypted) > 0:
            data_decrypted =  self.decrypt(self.withKey(self.serverPrivateKey), data_encrypted)
            self.handleMessageType(s, json.loads(data_decrypted))

          # client closed connection
          #else:
            #s.close()
            #self.selectList.remove(s)

    self.end()
    

  # =============================================================================================

  def handleMessageType(self, clientSocket, jsonMessage):
    if jsonMessage['messageType'] == 'loginAuth':
      self.validateTimestamp(time.time(), jsonMessage['timestamp'])
      loginAuthResponse = LoginAuthResponse(jsonMessage['nonce'], self.genTime())

      tempSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      tempSocket.connect((self.host, jsonMessage['srcPort']))
      
      self.sendEncrypted(loginAuthResponse.encode(), self.withKey(jsonMessage['clientPublicKey']), tempSocket)
      tempSocket.close()

    if jsonMessage['messageType'] == 'login':
      username = jsonMessage['username']
      password = jsonMessage['password']
      loginResponseMessage = None
      if username in self.users and password == self.users[username]:
        self.usersOnline[username] = (jsonMessage['srcPort'], jsonMessage['clientPublicKey'])
        loginResponseMessage = LoginResponseMessage(username, 'success')

        destPubKey = self.usersOnline[username][1]
        self.sendEncrypted(loginResponseMessage.encode(), self.withKey(destPubKey), clientSocket)

      else:
        loginResponseMessage = LoginResponseMessage(username, 'fail')

        self.sendEncrypted(loginResponseMessage.encode(), self.withKey(jsonMessage['clientPublicKey']), clientSocket)

    if jsonMessage['messageType'] == 'list':
      listMessage = ListResponseMessage(self.usersOnline.keys())
      destPubKey = self.usersOnline[jsonMessage['username']][1]

      self.sendEncrypted(listMessage.encode(), self.withKey(destPubKey), clientSocket)

    if jsonMessage['messageType'] == 'selectUser':
      self.debug("selecting user")
      toUser = jsonMessage['toUser']
      fromUser = jsonMessage['fromUser']
      nonce = jsonMessage['nonce']
      toUserPort = None

      if toUser in self.usersOnline:
        toUserPort = self.usersOnline[toUser][0]
        self.debug("selected user " + str(toUser) + " " + str(toUserPort))
      
        toUserPubKey = self.usersOnline[toUser][1]
        fromUserPubKey = self.usersOnline[fromUser][1]
        sessionKey = binascii.b2a_base64(self.genSessionKey())

        nsblock_auth3_raw = NeedhamSchroeder_Auth3(toUser, sessionKey, self.genTime())
        nsblock_auth3 = nsblock_auth3_raw.encode()
        nsblock_auth3_enc = binascii.b2a_base64(self.encrypt(self.withKey(toUserPubKey), nsblock_auth3))

        selectUserResponse = SelectUserResponseMessage(
          toUser, toUserPubKey, toUserPort, sessionKey, nonce, self.genTime(), nsblock_auth3_enc)

        self.sendEncrypted(selectUserResponse.encode(), self.withKey(fromUserPubKey), clientSocket)
      
      else:
        fromUserPubKey = self.usersOnline[fromUser][1]
        selectUserResponse = SelectUserResponseMessage(toUser)
              
        self.sendEncrypted(selectUserResponse.encode(), self.withKey(fromUserPubKey), clientSocket)

    if jsonMessage['messageType'] == 'logoutMessage':
      del self.usersOnline[jsonMessage['username']]
      clientSocket.close()
      self.selectList.remove(clientSocket)

  def end(self):
    print "Quitting server."
    for sock in self.selectList:
      sock.close()

    self.selectList = []
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

  # Load private key of server
  def loadServerPrivateKey(self):
    self.serverPrivateKey = self.file_read("array", "private_ckserver.pem")

  def withKey(self, unjoined):
    return "".join([str(e) for e in unjoined])


  # =============================================================================================
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

  def sendEncrypted(self, message, key, socket):
    socket.send(self.encrypt(key, message))

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

  def genTime(self):
    return time.time()

  def genSessionKey(self):
    symmKey = os.urandom(16)
    iv = os.urandom(16)
    return symmKey + iv   # generate a random symmetric key

  def validateTimestamp(self, timestampExpected, timestampReceived):
    self.debug("validating timestamp")
    try:
      if abs(timestampExpected - timestampReceived) > 60:
        print "[ERROR] Timestamp validation failed."
        # self.end()
    except:
      print "[ERROR] Timestamp validation failed."

# Start server
Server() 