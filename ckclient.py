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
from Message import SessionEstMessage


class Client:
  def __init__(self): 
    self.host = 'localhost'
    self.clientPort = random.randint(60000, 65000)
    self.serverPort = 50010
    self.size = 1024 
    self.user = ''

    self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.clientSocket.bind((self.host, self.clientPort))
    self.clientSocket.listen(5)

    self.selectList = [self.clientSocket, sys.stdin]
    self.running = 1

    self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serverSocket.connect((self.host, self.serverPort))
    self.selectList.append(self.serverSocket)

    self.privateSockets = {}

    self.sessionKey = ''
    self.clientKeys = {}

    self.run()

  def run(self):
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
          data = s.recv(self.size)
          self.handleMessageType(s, json.loads(data))

    self.end()


  def handleUserInput(self, line):
    if line == '\n':
      self.running = 0

    # login
    elif str.split(line)[0] == '<login>':
      loginMessage = LoginMessage(self.clientPort, str.split(line)[1], str.split(line)[2])
      print loginMessage.encode()
      self.serverSocket.send(loginMessage.encode())

    # request list of online users
    elif str.split(line)[0] == '<list>':
      listMessage = ListMessage(self.clientPort)
      self.serverSocket.send(listMessage.encode())

    # select user
    elif str.split(line)[0] == '<message>':
      selectUserMessage = SelectUserMessage(str.split(line)[1])
      self.serverSocket.send(selectUserMessage.encode())
      # self.establishNeedhamSchroeder(self.user, destuser)

    # received server message
    else:
      serverMessage = ServerMessage(self.clientPort, line)
      self.serverSocket.send(serverMessage.encode())

  def handleMessageType(self, serverSocket, jsonMessage):
    if jsonMessage['messageType'] == 'serverMessage':
      print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']

    if jsonMessage['messageType'] == 'loginResponse':
      if jsonMessage['status'] == 'success':
        print 'Login succeeded. Type `<list>` to see a list of online users to message!'
      else:
        print 'Invalid username or password.'

    if jsonMessage['messageType'] == 'listResponse':
      print 'Users currently online: ' + `jsonMessage['userList']`

    if jsonMessage['messageType'] == 'selectUserResponse':
      if jsonMessage['destinationPort'] != '':
        print jsonMessage['destinationPort']

        # TODO
        #sendPrivateMessage(jsonMessage['destinationPort'])
      else:
        print 'That user is not online. Please try a different user.'

    if jsonMessage['messageType'] == 'sessionEstablishment':
      self.handleNeedhamSchroeder(message)


  def sendPrivateMessage(self, destinationPort):
    privateSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.privateSockets[str(destinationPort)] = privateSocket
    privateSocket.connect((self.host, destinationPort))

  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)

  def establishNeedhamSchroeder(self, userid_a, userid_b):
    nonce = NONCE
    message = userid_a + userid_b + nonce


  def handleNeedhamSchroeder(self, message_encrypted):
    message = self.decrypt("MY USERID >> MY SHARED KEY", message_encrypted)

    if messageType == 'serverMessage':
      resp_session_key = message[0]
      resp_userid_b = message[1]
      resp_timestamp = message[2]
      resp_nonce_a = message[3]
      resp_message_b = message[4]

      validate("time", resp_timestamp)
      validate("nonce", resp_nonce_a)

      self.sessionKey = resp_session_key

      # SessionEstMessage(DESTINATION[port], DATA)
      sessionEstablishment = SessionEstMessage(resp_userid_b, resp_message_b)
      self.serverSocket.send(sessionEstablishment.encode())

    elif messageType == 'sessionEstablishment':
      # TODO


  def validate(self, data_type, data):
    if data_type == "time":
      return data  # TODO: validate time; if false, alert user and kill program.
    if data_type == "nonce":
      return data  # TODO: validate nonce; if false, alert user and kill program.


  def encrypt(self, userid, data):
    encrypt_key = self.clientKeys[userid]
    return data   # TODO: message encrypting

  def decrypt(self, userid, data):
    decrypt_key = self.clientKeys[userid]
    return data   # TODO: message encrypting



  def end(self):
    sessionKey = 'ended'
    self.clientSocket.close()
    sys.exit()


# Start a Client instance
Client()
