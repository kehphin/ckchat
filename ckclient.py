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


class Client:
  def __init__(self): 
    self.host = 'localhost'
    self.clientPort = random.randint(60000, 65000)
    self.serverPort = 50010
    self.size = 1024 

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
    self.currentPrivateConnection = None # (socket, port, username)

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

    self.clientSocket.close()

  def handleUserInput(self, line):
    if line == '\n':
      self.running = 0

    # login
    elif str.split(line)[0] == '<login>':
      loginMessage = LoginMessage(self.clientPort, str.split(line)[1], str.split(line)[2])
      self.serverSocket.send(loginMessage.encode())

    # request list of online users
    elif str.split(line)[0] == '<list>':
      listMessage = ListMessage(self.clientPort)
      self.serverSocket.send(listMessage.encode())

    # select user
    elif str.split(line)[0] == '<message>':
      selectUserMessage = SelectUserMessage(str.split(line)[1])
      self.serverSocket.send(selectUserMessage.encode())

    # private message enabled with someone
    elif self.currentPrivateConnection != None:
      privateMessage = PrivateMessage(self.clientPort, self.currentPrivateConnection['port'], line)
      self.currentPrivateConnection['socket'].send(privateMessage.encode())

    # received server message
    else:
      serverMessage = ServerMessage(self.clientPort, line)
      self.serverSocket.send(serverMessage.encode())

  def handleMessageType(self, serverSocket, jsonMessage):
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
      self.currentPrivateConnection['socket'].send(privateMessageResponse.encode())

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

  def sanitizeInput(self):
    # Some command line manipulation to get messages to display properly
    PREVIOUS_LINE = '\x1b[1A'
    DELETE_LINE = '\x1b[2K'
    print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)

# Start a Client instance
Client()
