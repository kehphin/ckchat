#!/usr/bin/env python


import select
import socket
import sys
import random
import json
import pprint

from Message import ServerMessage
from Message import LoginMessage
from Message import ListMessage
from Message import SelectUserMessage
from Message import EstablishPrivateMessage
from Message import EstablishPrivateMessageResponse
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
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption

class Client:
  def __init__(self):
    self.host = 'localhost'
    self.clientPort = random.randint(60000, 65000)
    self.serverPort = 50020
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
    self.currentConnections = {}
    self.messageQueue = []

    self.debugMode = False

    self.run()

  def run(self):
    print "Chat client started. \n\nPlease enter your username and password in the format: <username> <password>\n\nPress `enter` at any time to exit."

    self.generateClientKeyPair()
    self.loadServerPublicKey()

    while self.running:
      ready,outputready,exceptready = select.select(self.selectList,[],[])

      for s in ready:
        # handle own socket
        if s == self.clientSocket:
          client, address = self.clientSocket.accept()
          self.selectList.append(client)

        # handle user input
        elif s == sys.stdin:
          self.handleUserInput(sys.stdin.readline()) 

        # handle message from server
        else:
          self.debug("receiving incoming message.")
          data_encrypted = s.recv(self.size)
          data_decrypted = self.decrypt(self.withKey(self.clientPrivateKey), data_encrypted)
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

  # Deserializes the public/private keys
  def deserialize_key(self, key_serialized, key_type):
    serialized_key = None
    if key_type == "private":
      serialized_key = serialization.load_pem_private_key(
        key_serialized, password=None, backend=default_backend()
      )
    elif key_type == "public":
      serialized_key = serialization.load_pem_public_key(
        key_serialized, backend=default_backend()
      )   

    return serialized_key

  # Enables debug messages
  def debug(self, text):
    if self.debugMode:
      print "[DEBUG] " + text

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

  # Load public key of server
  def loadServerPublicKey(self):
    self.serverPublicKey = self.file_read("array", "public_ckserver.pub")

  def withKey(self,unjoined):
    return "".join([str(e) for e in unjoined])

  # =============================================================================================

  def handleUserInput(self, line):
    if line == '\n':
      self.running = 0

    # request list of online users
    elif str.split(line)[0] == 'list':
      if self.username:
        listMessage = ListMessage(self.clientPort, self.username)
        self.sendEncrypted(listMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket);
        self.debug("list request encoded and sent to server")
      else:
        print "You are not currently logged in. \nPlease enter your username and password in the format: <username> <password>"

    # select user
    elif str.split(line)[0] == 'send':
      if len(str.split(line)) < 3:
        print "Invalid send format. Please try again."

      if self.username:
        lineArray = str.split(line)
        toUser = lineArray[1]
        toUserMessage = " ".join(lineArray[2:])

        if toUser in self.currentConnections:
          userInfo = self.currentConnections[toUser]
          privateMessage = PrivateMessage(self.clientPort, self.username, userInfo['port'], toUserMessage)
          self.sendEncrypted(privateMessage.encode(), self.withKey(userInfo['publicKey']), userInfo['socket']);

          self.sanitizeInput()

        else:
          self.messageQueue.append((toUser, toUserMessage))

          selectUserMessage = SelectUserMessage(self.username, toUser)
          self.sendEncrypted(selectUserMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket);
          self.sanitizeInput()
          self.debug("selectUserMessage encoded and sent to server")
          print "Attempting to start session with " + toUser + "."

    elif len(str.split(line)) == 2:
      loginMessage = LoginMessage(self.clientPort, str.split(line)[0], str.split(line)[1], self.clientPublicKey)
      self.sendEncrypted(loginMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket);
      self.debug("login information sent to server")

      self.sanitizeInput()

    elif self.username:
      print "Invalid command. Please try again."

    else:
      print "You are not currently logged in. \n\nPlease enter your username and password in the format: <username> <password>"


    # private message enabled with someone
    #elif self.currentPrivateConnection != None:
    ##  privateMessage = PrivateMessage(self.clientPort, self.currentPrivateConnection['port'], line)
     # self.sendEncrypted(privateMessage.encode(), self.withKey(self.currentPrivateConnection['publicKey']), self.currentPrivateConnection['socket']);


  def handleMessageType(self, serverSocket, jsonMessage):
    # TODO: ADD TRY-CATCH TO HANDLE: ValueError: No JSON object could be decoded

    if jsonMessage['messageType'] == 'serverMessage':
      print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']

    if jsonMessage['messageType'] == 'loginResponse':
      if jsonMessage['status'] == 'success':
        self.username = jsonMessage['username']
        print 'Login succeeded. Type `list` to see a list of online users to message!'
      else:
        print 'Invalid username or password.'

    if jsonMessage['messageType'] == 'listResponse':
      print "Users currently online:"
      for element in jsonMessage['userList']:
        # print 'Users currently online: ' + jsonMessage['userList']
         print "  * " + str(element)

    if jsonMessage['messageType'] == 'selectUserResponse':

      self.debug("received selectUserResponse")
      """
      self.debug("received: " + str(jsonMessage['toUser']))
      self.debug("received: " + str(jsonMessage['toUserPubKey']))
      self.debug("received: " + str(jsonMessage['toUserPort']))
      self.debug("received: " + str(jsonMessage['sessionKey']))
      self.debug("received: " + str(jsonMessage['nonceReturned']))
      self.debug("received: " + str(jsonMessage['timestamp']))
      self.debug("received: " + str(jsonMessage['forwardBlock']))
      """

      if jsonMessage['toUserPort'] != '':
        self.setPrivateMessageMode(jsonMessage['toUser'], jsonMessage['toUserPubKey'], jsonMessage['toUserPort'])
      else:
        print jsonMessage['toUser'] + " is unavailable. Please try a different user."

    if jsonMessage['messageType'] == 'establishPrivateMessage':
      currentPrivateConnection = {
        'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        'port': jsonMessage['srcPort'],
        'publicKey': jsonMessage['srcPublicKey']
      }

      self.currentConnections[jsonMessage['srcUsername']] = currentPrivateConnection

      currentPrivateConnection['socket'].connect((self.host, jsonMessage['srcPort']))

      establishPrivateMessageResponse = EstablishPrivateMessageResponse(self.username, "success")
      self.sendEncrypted(establishPrivateMessageResponse.encode(), self.withKey(jsonMessage['srcPublicKey']), currentPrivateConnection['socket'])
          
    if jsonMessage['messageType'] == 'establishPrivateMessageResponse':
      for msg in self.messageQueue:
        if msg[0] == jsonMessage['username']:
          privateMessage = PrivateMessage(self.clientPort, self.username, self.currentConnections[jsonMessage['username']]['port'], msg[1])
          self.sendEncrypted(privateMessage.encode(), self.withKey(self.currentConnections[jsonMessage['username']]['publicKey']), self.currentConnections[jsonMessage['username']]['socket'])

      self.messageQueue = filter(lambda x: x[0] != jsonMessage['username'], self.messageQueue)

    if jsonMessage['messageType'] == 'privateMessage':
      fromUser = self.currentConnections[jsonMessage['srcUsername']]
      print jsonMessage['srcUsername'] + " >>>  " + str(jsonMessage['message'])
      privateMessageResponse = PrivateMessageResponse(self.clientPort, fromUser['port'], jsonMessage['message'])
      self.debug("setting currentPrivateConnection")
      self.sendEncrypted(privateMessageResponse.encode(), self.withKey(fromUser['publicKey']), fromUser['socket'])

    if jsonMessage['messageType'] == 'privateMessageResponse':
      print "YOU" + " >>>  " + str(jsonMessage['message'])


  def setPrivateMessageMode(self, toUser, toUserPubKey, toUserPort):
    currentPrivateConnection = {
      'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
      'port': toUserPort,
      'publicKey': toUserPubKey
    }

    self.currentConnections[toUser] = currentPrivateConnection;

    currentPrivateConnection['socket'].connect((self.host, toUserPort))

    establishPrivateMessage = EstablishPrivateMessage(self.clientPort, self.username, self.clientPublicKey)
    self.sendEncrypted(establishPrivateMessage.encode(), self.withKey(toUserPubKey), currentPrivateConnection['socket'])

  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)


  def encrypt(self, public_key_serialized, data):
    try:
      self.debug("encrypting data...")

      public_key = self.deserialize_key(public_key_serialized, "public")

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


  def decrypt(self, private_key_serialized, ciphertext):
    try:
      self.debug("decrypting data...")
      private_key = self.deserialize_key(private_key_serialized, "private")

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

  def sendEncrypted(self, message, key, socket):
    socket.send(self.encrypt(key, message))

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
