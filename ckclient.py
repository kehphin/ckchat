#!/usr/bin/env python


import select
import socket
import sys
import random
import json
import pprint
import time

from Message import LoginAuth
from Message import LoginMessage
from Message import ListMessage
from Message import SelectUserMessage
from Message import EstablishPrivateMessage
from Message import EstablishPrivateMessageResponse
from Message import PrivateMessage
from Message import PrivateMessageResponse
from Message import LogoutMessage
from Message import PrivateEncryptedSubmessage

import os
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

class Client:
  def __init__(self):
    self.host = 'localhost'
    self.clientPort = random.randint(60000, 65000)
    self.serverPort = 50025
    self.size = 10000

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

  # runs the program
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

        # handle incoming message
        else:
          self.debug("receiving incoming message.")
          data_encrypted = s.recv(self.size)
          if len(data_encrypted) > 0:
            data_decrypted = self.decrypt(self.withKey(self.clientPrivateKey), data_encrypted)
            self.handleMessageType(s, json.loads(data_decrypted))

    self.end()

  # =============================================================================================
  # handles the user's input
  def handleUserInput(self, line):
    if line == '\n':
      self.running = 0

    # request list of online users
    elif str.split(line)[0] == 'list':
      if self.username:
        listMessage = ListMessage(self.clientPort, self.username)
        self.sendEncrypted(listMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket)
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
          self.sendPrivateEncrypted(privateMessage.encode(), self.withKey(userInfo['publicKey']), userInfo['sessionKey'], userInfo['socket'])

          self.sanitizeInput()

        else:
          self.messageQueue.append((toUser, toUserMessage))
          self.nonceSent = self.genNonce()
          self.usernameSent = toUser

          selectUserMessage = SelectUserMessage(self.username, toUser, self.nonceSent)
          self.sendEncrypted(selectUserMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket)
          self.sanitizeInput()
          self.debug("selectUserMessage encoded and sent to server")
          print "Attempting to start session with " + toUser + ".\n"

    # login
    elif len(str.split(line)) == 2:
      if self.username == None:
        usernameInput = str.split(line)[0]
        passwordInput = str.split(line)[1]
        loginMessage = (usernameInput, passwordInput)
        self.messageQueue.append(loginMessage)
        self.loginAuthNonce = self.genNonce()
        loginAuthMessage = LoginAuth(self.clientPort, self.loginAuthNonce, self.genTime(), self.clientPublicKey)
        self.sendEncrypted(loginAuthMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket)
        self.debug("login information sent to server")

        self.sanitizeInput()
      else:
        print "You are already logged in as " + self.username + "!"

    elif self.username:
      print "Invalid command. Please try again."

    else:
      print "You are not currently logged in. \n\nPlease enter your username and password in the format: <username> <password>"

  # handles received messages
  def handleMessageType(self, serverSocket, jsonMessage):
    # TODO: ADD TRY-CATCH TO HANDLE: ValueError: No JSON object could be decoded

    if jsonMessage['messageType'] == 'loginAuthResponse':
      self.validateNonce(self.loginAuthNonce, jsonMessage['nonce'])
      self.validateTimestamp(time.time(), jsonMessage['timestamp'])

      messageToSend = self.messageQueue.pop()

      loginMessage = LoginMessage(self.clientPort, messageToSend[0], messageToSend[1], self.clientPublicKey)
      self.sendEncrypted(loginMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket)

    elif jsonMessage['messageType'] == 'loginResponse':
      self.debug("received login response")
      if jsonMessage['status'] == 'success':
        self.username = jsonMessage['username']
        print 'Login succeeded. Type `list` to see a list of online users to message!'
      elif jsonMessage['status'] == 'alreadyLoggedIn':
        print 'You are already logged in in another session. \nPlease logout the other session to start a new session.'
      elif jsonMessage['status'] == 'fail':
        print 'Invalid username or password.'
      else:
        print 'Invalid command'

    elif jsonMessage['messageType'] == 'listResponse':
      print "Users currently online:"
      for element in jsonMessage['userList']:
        # print 'Users currently online: ' + jsonMessage['userList']
         print "  * " + str(element)

    elif jsonMessage['messageType'] == 'selectUserResponse':

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

      self.validateUsername(self.usernameSent, jsonMessage['toUser'])
      self.validateNonce(self.nonceSent, jsonMessage['nonceReturned'])
      self.validateTimestamp(time.time(), jsonMessage['timestamp'])

      if jsonMessage['toUserPort'] != '':
        self.setPrivateMessageMode(jsonMessage['toUser'], jsonMessage['toUserPubKey'], jsonMessage['sessionKey'], jsonMessage['toUserPort'], jsonMessage['forwardBlock'])
      else:
        print jsonMessage['toUser'] + " is unavailable. Please try a different user."

    elif jsonMessage['messageType'] == 'establishPrivateMessage':
      nsBlockEncrypted = binascii.a2b_base64(jsonMessage['forwardBlock'])
      nsBlockDecrypted = json.loads(self.decrypt(self.withKey(self.clientPrivateKey), nsBlockEncrypted))

      self.validateUsername(self.username, nsBlockDecrypted['destinationUsername'])
      self.validateTimestamp(time.time(), nsBlockDecrypted['serverTimestamp'])

      currentPrivateConnection = {
        'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        'port': jsonMessage['srcPort'],
        'publicKey': jsonMessage['srcPublicKey'],
        'sessionKey': nsBlockDecrypted['sessionKey']
      }

      self.currentConnections[jsonMessage['srcUsername']] = currentPrivateConnection

      currentPrivateConnection['socket'].connect((self.host, jsonMessage['srcPort']))

      establishPrivateMessageResponse = EstablishPrivateMessageResponse(self.username, jsonMessage['nonce'])
      self.sendEncrypted(establishPrivateMessageResponse.encode(), self.withKey(jsonMessage['srcPublicKey']), currentPrivateConnection['socket'])
          
    elif jsonMessage['messageType'] == 'establishPrivateMessageResponse':
      self.validateNonce(self.privateMessageEstablishmentNonce, jsonMessage['nonce'])

      for msg in self.messageQueue:
        if msg[0] == jsonMessage['username']:
          toPort = self.currentConnections[jsonMessage['username']]['port']
          toPublicKey = self.currentConnections[jsonMessage['username']]['publicKey']
          toSocket = self.currentConnections[jsonMessage['username']]['socket']
          toSessionKey = self.currentConnections[jsonMessage['username']]['sessionKey']

          privateMessage = PrivateMessage(self.clientPort, self.username, toPort, msg[1])
          self.sendPrivateEncrypted(privateMessage.encode(), self.withKey(toPublicKey), toSessionKey, toSocket)

      self.messageQueue = filter(lambda x: x[0] != jsonMessage['username'], self.messageQueue)

    elif jsonMessage['messageType'] == 'logoutMessage':
      user = jsonMessage['username']
      self.currentConnections[user]['socket'].close()
      del self.currentConnections[user]

      print user + " has logged out."

    # encrypted private message
    elif len(jsonMessage) > 0:
      data_decrypted = json.loads(self.decryptPrivateMessage(jsonMessage))

      if data_decrypted['messageType'] == 'privateMessage':
        fromUser = self.currentConnections[data_decrypted['srcUsername']]
        print data_decrypted['srcUsername'] + " >>>  " + str(data_decrypted['message'])
        privateMessageResponse = PrivateMessageResponse(self.clientPort, fromUser['port'], data_decrypted['message'])
        self.debug("setting currentPrivateConnection")
        self.sendPrivateEncrypted(privateMessageResponse.encode(), self.withKey(fromUser['publicKey']), fromUser['sessionKey'], fromUser['socket'])

      elif data_decrypted['messageType'] == 'privateMessageResponse':
        print "YOU" + " >>>  " + str(data_decrypted['message'])

  # terminates the program
  def end(self):
    logoutMessage = LogoutMessage(self.username)
    # disconnect from server
    self.sendEncrypted(logoutMessage.encode(), self.withKey(self.serverPublicKey), self.serverSocket)
    self.clientSocket.close()

    # disconnect from all clients
    for user in self.currentConnections:
      userDetails = self.currentConnections[user]
      self.sendEncrypted(logoutMessage.encode(), self.withKey(userDetails['publicKey']), userDetails['socket'])
      userDetails['socket'].close()
          
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

  # generates a client key pair
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

  # generic function for key joining
  def withKey(self,unjoined):
    return "".join([str(e) for e in unjoined])

  # session initialization
  def setPrivateMessageMode(self, toUser, toUserPubKey, sessionKey, toUserPort, nsBlock):
    currentPrivateConnection = {
      'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
      'port': toUserPort,
      'publicKey': toUserPubKey,
      'sessionKey': sessionKey
    }

    self.currentConnections[toUser] = currentPrivateConnection;

    currentPrivateConnection['socket'].connect((self.host, toUserPort))

    self.privateMessageEstablishmentNonce = self.genNonce()

    establishPrivateMessage = EstablishPrivateMessage(self.clientPort, self.username, self.clientPublicKey, nsBlock, self.privateMessageEstablishmentNonce)
    self.sendEncrypted(establishPrivateMessage.encode(), self.withKey(toUserPubKey), currentPrivateConnection['socket'])

  # sanitizes the user's input
  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)

  # encrypts given data with the asymmetric key
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

  # decrypts given data with the asymmetric key
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

  # encrypts with the symmetric key
  def encryptSymm(self, message, key):
    symkey = key[:16]
    iv = key[16:]

    data_padded = self.enpad(message, 16)
    cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(data_padded) + encryptor.finalize()

    return encrypted_message

  # decrypts with the symmetric key
  def decryptSymm(self, message, key):
    message = binascii.a2b_base64(message)
    key = binascii.a2b_base64(key)
    # Separate the encrypted symmetric key from the encrypted data
    symkey = key[:16]
    iv = key[16:]

    # Decrypt the data then remove padding
    cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data_padded = decryptor.update(message) + decryptor.finalize()
    data = self.depad(data_padded)

    return data

  # decrypts a private message
  def decryptPrivateMessage(self, message):
    user = message['username']
    sessionKey = self.currentConnections[user]['sessionKey']

    decryptedMessage = self.decryptSymm(message['message'], sessionKey)
  
    return decryptedMessage
    
  # helper function to send encrypted messages
  def sendEncrypted(self, message, key, socket):
    socket.send(self.encrypt(key, message))

  # {message: <msg encrypted by session key>, username: <username>}pubkey
  def sendPrivateEncrypted(self, message, pubKey, sessionKey, socket):
    sessionKey = binascii.a2b_base64(sessionKey)

    privateEncryptedSubmessage = PrivateEncryptedSubmessage(binascii.b2a_base64(self.encryptSymm(message, sessionKey)), self.username)
    outerEncrypt = self.encrypt(pubKey, privateEncryptedSubmessage.encode())

    socket.send(outerEncrypt)

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

  # generates a nonce
  def genNonce(self):
    return random.randint(10000000, 99999999)

  # generates a timestamp
  def genTime(self):
    return time.time()

  # validates a timestamp (default set to 60 seconds of validity)
  def validateTimestamp(self, timestampExpected, timestampReceived):
    self.debug("validating timestamp")
    try:
      if abs(timestampExpected - timestampReceived) > 60:
        print "[ERROR] Timestamp validation failed."
        self.end()
    except:
      print "[ERROR] Timestamp validation failed."
      self.end()

  # validates a nonce
  def validateNonce(self, nonceExpected, nonceReceived):
    self.debug("validating the nonce returned")
    try:
      if nonceExpected != nonceReceived:
        print "[ERROR] Nonce validation failed."
        self.end()
    except:
      print "[ERROR] Nonce validation failed."
      self.end()

  # validates a username
  def validateUsername(self, usernameExpected, usernameReceived):
    self.debug("validating username")
    try:
      if usernameExpected != usernameReceived:
        print "[ERROR] Username validation failed."
        self.end()
    except:
      print "[ERROR] Username validation failed."
      self.end()

# Start a Client instance
Client()
