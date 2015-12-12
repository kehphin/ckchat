#!/usr/bin/env python


import select
import socket
import sys
import random
import json

from Message import ServerMessage
from Message import LoginMessage
from Message import ListMessage
from Message import SelectUserMessage
from Message import EstablishPrivateMessage
from Message import PrivateMessage
from Message import PrivateMessageResponse

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

class Client:
  def __init__(self): 
    self.host = 'localhost'
    self.clientPort = random.randint(60000, 65000)
    self.serverPort = 50010
    self.size = 1024 
    self.clientPrivateKey = None
    self.clientPublicKey = None

    self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.clientSocket.bind((self.host, self.clientPort))
    self.clientSocket.listen(5)

    self.selectList = [self.clientSocket, sys.stdin]
    self.running = 1

    self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serverSocket.connect((self.host, self.serverPort))
    self.selectList.append(self.serverSocket)

    self.username = None
    self.privateSockets = {}
    self.currentPrivateConnection = None # (socket, port, username, session_key)

    self.debugMode = True


    self.run()

  def run(self):
    self.clientPrivateKey = self.file_read("array", "cs4740_key1.pem")
    self.clientPublicKey = self.file_read("array", "cs4740_key1.pub")

    while self.running:
      ready,outputready,exceptready = select.select(self.selectList,[],[])

      for s in ready:
        # handle own socket
        if s == self.clientSocket:
          client, address = self.clientSocket.accept()
          self.selectList.append(client)

        # handle user input
        elif s == sys.stdin:
          self.sanitizeInput()
          self.handleUserInput(sys.stdin.readline()) 

        # handle message from server
        else:
          self.debug("receiving incoming message.")
          clientPrivateKey = "".join(self.clientPrivateKey)
          data_encrypted = s.recv(self.size)
          data_decrypted = self.decrypt(clientPrivateKey, data_encrypted)
          self.handleMessageType(s, json.loads(data_decrypted))

    self.end()

  def end(self):
    self.clientSocket.close()
    sys.exit()

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
    serialized_key = None
    if key_type == "private":
      serialized_key = serialization.load_pem_private_key(
        key_unserialized, password=None, backend=default_backend()
        )
    elif key_type == "public":
      serialized_key = serialization.load_pem_public_key(
        key_unserialized, backend=default_backend()
        )   
    return serialized_key

  # Enables debug messages
  def debug(self, text):
    if self.debugMode:
      print "[DEBUG] " + text

  # =============================================================================================
  def handleUserInput(self, line):
    if line == '\n':
      self.running = 0

    # login
    elif str.split(line)[0] == '<login>':
      clientPublicKeyRaw = self.clientPublicKey
      loginMessage = LoginMessage(self.clientPort, str.split(line)[1], str.split(line)[2], clientPublicKeyRaw)
      # self.serverSocket.send(self.encrypt("SERVER_PUBLIC_KEY", loginMessage.encode()))
      self.serverSocket.send(loginMessage.encode())
      self.debug("login information sent to server")

    # request list of online users
    elif str.split(line)[0] == '<list>':
      listMessage = ListMessage(self.clientPort, self.username)
      self.serverSocket.send(listMessage.encode())
      self.debug("list request encoded and sent to server")

    # select user
    elif str.split(line)[0] == '<message>':
      selectUserMessage = SelectUserMessage(self.username, str.split(line)[1])
      self.serverSocket.send(selectUserMessage.encode())
      self.debug("selectUserMessage encoded and sent to server")

    # private message enabled with someone
    elif self.currentPrivateConnection != None:
      privateMessage = PrivateMessage(self.clientPort, self.currentPrivateConnection['port'], line)
      clientPublicKey = "".join(self.clientPublicKey)
      # self.currentPrivateConnection['socket'].send(privateMessage.encode())
      self.currentPrivateConnection['socket'].send(self.encrypt(clientPublicKey, privateMessage.encode()))

    # received server message
    else:
      serverMessage = ServerMessage(self.clientPort, line)
      self.serverSocket.send(serverMessage.encode())


  def handleMessageType(self, serverSocket, jsonMessage):
    # TODO: ADD TRY-CATCH TO HANDLE: ValueError: No JSON object could be decoded

    if jsonMessage['messageType'] == 'serverMessage':
      print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']

    if jsonMessage['messageType'] == 'loginResponse':
      if jsonMessage['status'] == 'success':
        self.username = jsonMessage['username']
        print 'Login succeeded. Type `<list>` to see a list of online users to message!'
      else:
        print 'Invalid username or password.'

    if jsonMessage['messageType'] == 'listResponse':
      print "Users currently online:"
      for element in jsonMessage['userList']:
        # print 'Users currently online: ' + jsonMessage['userList']
         print "  * " + str(element)

    if jsonMessage['messageType'] == 'selectUserResponse':
      self.debug("received selectUserResponse")

      json_destinationPort = jsonMessage['destinationPort']
      json_destinationUsername = jsonMessage['destinationUsername']
      json_sessionKey = jsonMessage['sessionKey']
      json_nonceReturned = jsonMessage['nonceReturned']
      json_timestamp = jsonMessage['timestamp']
      json_nsblock_auth3 = jsonMessage['nsblock_auth3']

      self.debug("received: " + str(json_destinationPort))
      self.debug("received: " + str(json_destinationUsername))
      self.debug("received: " + str(json_sessionKey))
      self.debug("received: " + str(json_nonceReturned))
      self.debug("received: " + str(json_timestamp))
      self.debug("received: " + str(json_nsblock_auth3))

      self.validateUsername("THE_USERNAME_I_REQUESTED_TO_MESSAGE", json_destinationUsername)
      self.validateNonce("NONCE_EXPECTED", json_nonceReturned)
      self.validateTimestamp("TIMESTAMP_EXPECTED", json_timestamp)

      if jsonMessage['destinationPort'] != '':
        self.setPrivateMessageMode(jsonMessage['destinationPort'], jsonMessage['destinationUsername'], jsonMessage['nsblock_auth3'])
      else:
        print 'That user is not online. Please try a different user.'

    if jsonMessage['messageType'] == 'establishPrivateMessage':
      self.debug("Received establishPrivateMessage")
      self.debug("Needham Schroeder Auth3 Encrypted Block (Unencrypted atm...):")
      self.debug(str(jsonMessage['nsblock_auth3']))
      # clientPrivateKey = "".join(self.clientPrivateKey)
      # data_encrypted = jsonMessage['nsblock_auth3']
      # data_decrypted = self.decrypt(clientPrivateKey, data_encrypted)
      # self.debug(data_decrypted)

      json_nsblock_username = jsonMessage['nsblock_auth3'] # username within the NeedhamSchroeder_Auth3 message
      json_timestamp = jsonMessage['timestamp']
      
      self.validateUsername("MY_USERNAME", json_nsblock_username)
      self.validateTimestamp("TIMESTAMP_EXPECTED", json_timestamp)

      # store received nonce and return to clientA


      self.currentPrivateConnection = {
        'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        'port': jsonMessage['srcPort'],
        'username': jsonMessage['srcUsername']
      }
      self.currentPrivateConnection['socket'].connect((self.host, jsonMessage['srcPort']))

    if jsonMessage['messageType'] == 'privateMessage':
      print str(self.currentPrivateConnection['username']).upper().rjust(10) + " >>>  " + str(jsonMessage['message'])
      privateMessageResponse = PrivateMessageResponse(self.clientPort, self.currentPrivateConnection['port'], jsonMessage['message'])
      self.debug("setting currentPrivateConnection")
      clientPublicKey = "".join(self.clientPublicKey)
      self.currentPrivateConnection['socket'].send(self.encrypt(clientPublicKey, privateMessageResponse.encode()))

    if jsonMessage['messageType'] == 'privateMessageResponse':
      print "YOU".rjust(10) + " >>>  " + str(jsonMessage['message'])


  def setPrivateMessageMode(self, destinationPort, destinationUsername, nsblock_auth3):
    self.currentPrivateConnection = {
      'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
      'port': destinationPort,
      'username': destinationUsername
    }

    self.currentPrivateConnection['socket'].connect((self.host, destinationPort))

    establishPrivateMessage = EstablishPrivateMessage(self.clientPort, self.username, "CLIENT_TIMESTAMP", "NEW_NONCE", nsblock_auth3)
    clientPublicKey = "".join(self.clientPublicKey)
    self.currentPrivateConnection['socket'].send(self.encrypt(clientPublicKey, establishPrivateMessage.encode()))

    print 'Connected to ' + destinationUsername + ' on Port: ' + `destinationPort`
    print 'You may now begin chatting.'


  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)


  def validateTimestamp(self, timestampExpected, timestampReceived):
    self.debug("validating timestamp")

  def validateNonce(self, nonceExpected, nonceReceived):
    self.debug("validating the nonce returned")

  def validateUsername(self, usernameExpected, usernameReceived):
    self.debug("validating username")


  def encrypt(self, public_key_unserialized, data):
    try:
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
    except ValueError:
      print "Encryption error."
      self.end()


  def decrypt(self, private_key_unserialized, ciphertext):
    try:
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

    except ValueError:
      print "Decryption error."
      self.end()


  # =============================================================================================
  # Adds padding to a data
  def enpad(self, data, hash_length):
    pad_size = hash_length - len(data) % hash_length
    padding = pad_size * chr(pad_size)
    return data + padding

  # Removes padding from a data
  def depad(self, data):
    univalue = ord(data[-1])
    return data[0:-univalue]


# Start a Client instance
Client()
