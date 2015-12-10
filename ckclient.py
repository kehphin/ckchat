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
    self.clientPrivateKey = self.import_key("cs4740_key1.pem", "private")
    self.clientPublicKey = self.import_key("cs4740_key1.pub", "public")

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
          data_encrypted = s.recv(self.size)
          data_decrypted =  self.decrypt("MY_PRIVATE_KEY", data_encrypted)
          self.handleMessageType(s, json.loads(data_decrypted))

    self.clientSocket.close()

  # =============================================================================================
  # Opens and reads a file
  def file_read(self, filename):
    print "reading input file..."
    with open(filename) as f:
      self.fileinput_content = f.read()

  # Imports the public/private keys
  def import_key(self, key_path, key_type):
      imported_key = ""
      if key_type == "private":
        with open(key_path, "rb") as key_file:
          imported_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
      elif key_type == "public":
        with open(key_path, "rb") as key_file:
          imported_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )
        
        return imported_key

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
      clientPublicKeyRaw = "CLIENT_PUBLIC_KEY"
      loginMessage = LoginMessage(self.clientPort, str.split(line)[1], str.split(line)[2], clientPublicKeyRaw)
      self.serverSocket.send(self.encrypt("SERVER_PUBLIC_KEY", loginMessage.encode()))
      self.debug("login information sent to server.")

    # request list of online users
    elif str.split(line)[0] == '<list>':
      listMessage = ListMessage(self.clientPort)
      self.serverSocket.send(listMessage.encode())

    # select user
    elif str.split(line)[0] == '<message>':
      selectUserMessage = SelectUserMessage(str.split(line)[1])
      self.debug("about to send selectUserMessage")
      self.serverSocket.send(selectUserMessage.encode())
      self.debug("selectUserMessage encoded and sent")

    # private message enabled with someone
    elif self.currentPrivateConnection != None:
      privateMessage = PrivateMessage(self.clientPort, self.currentPrivateConnection['port'], line)
      self.currentPrivateConnection['socket'].send(privateMessage.encode())

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
      print 'Users currently online: ' + `jsonMessage['userList']`

    if jsonMessage['messageType'] == 'selectUserResponse':
      self.debug("received selectUserResponse")
      self.debug("received: " + str(jsonMessage['destinationPort']))
      self.debug("received: " + str(jsonMessage['destinationUsername']))
      self.debug("received: " + str(jsonMessage['sessionKey']))
      self.debug("received: " + str(jsonMessage['nonceReturned']))
      self.debug("received: " + str(jsonMessage['timestamp']))
      self.debug("received: " + str(jsonMessage['forwardBlock']))

      if jsonMessage['destinationPort'] != '':
        self.setPrivateMessageMode(jsonMessage['destinationPort'], jsonMessage['destinationUsername'])
      else:
        print 'That user is not online. Please try a different user.'

    if jsonMessage['messageType'] == 'establishPrivateMessage':
      self.currentPrivateConnection = {
        'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        'port': jsonMessage['srcPort'],
        'username': jsonMessage['srcUsername']
      }

      self.currentPrivateConnection['socket'].connect((self.host, jsonMessage['srcPort']))

    if jsonMessage['messageType'] == 'privateMessage':
      print 'From ' + `self.currentPrivateConnection['username']` + ': ' + jsonMessage['message']
      privateMessageResponse = PrivateMessageResponse(self.clientPort, self.currentPrivateConnection['port'], jsonMessage['message'])
      self.debug("setting currentPrivateConnection")
      self.currentPrivateConnection['socket'].send(privateMessageResponse.encode())
      self.debug(str(self.currentPrivateConnection))

    if jsonMessage['messageType'] == 'privateMessageResponse':
      print 'To ' + `self.currentPrivateConnection['username']` + ': ' + jsonMessage['message']


  def setPrivateMessageMode(self, destinationPort, destinationUsername):
    self.currentPrivateConnection = {
      'socket': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
      'port': destinationPort,
      'username': destinationUsername
    }

    self.currentPrivateConnection['socket'].connect((self.host, destinationPort))

    establishPrivateMessage = EstablishPrivateMessage(self.clientPort, self.username)
    self.currentPrivateConnection['socket'].send(establishPrivateMessage.encode())

    print 'Connected to ' + destinationUsername + ' on Port: ' + `destinationPort`
    print 'You may now begin chatting.'


  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)


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
