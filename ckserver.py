#!/usr/bin/env python


import select
import socket
import sys
import json

from Message import ListResponseMessage
from Message import LoginResponseMessage
from Message import SelectUserResponseMessage


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

    self.usersOnline = {}

    self.users = {
      'kevin': '123',
      'bob': 'enter'
    }

    self.clientKeys = {}

    self.run()

  def run(self):
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
          data = s.recv(self.size)
          if len(data) > 0:
            self.handleMessageType(s, json.loads(data))

          # client closed connection
          else:
            s.close()
            self.selectList.remove(s)

    self.serverSocket.close()

  def handleMessageType(self, clientSocket, jsonMessage):
    if jsonMessage['messageType'] == 'serverMessage':
      print 'From ' + `jsonMessage['srcPort']` + ': ' + jsonMessage['message']
      clientSocket.send(json.dumps(jsonMessage))

    if jsonMessage['messageType'] == 'login':
      if jsonMessage['username'] in self.users and jsonMessage['password'] == self.users[jsonMessage['username']]:
        self.usersOnline[jsonMessage['username']] = jsonMessage['srcPort']

        loginResponseMessage = LoginResponseMessage('success')
        clientSocket.send(loginResponseMessage.encode())

      else:
        loginResponseMessage = LoginResponseMessage('fail')
        clientSocket.send(loginResponseMessage.encode())

    if jsonMessage['messageType'] == 'list':
      listMessage = ListResponseMessage(self.usersOnline.keys())
      clientSocket.send(listMessage.encode())

    if jsonMessage['messageType'] == 'selectUser':
      user = jsonMessage['username']
      destinationPort = ''
      if user in self.usersOnline:
        destinationPort = self.usersOnline[user]

      selectUserResponse = SelectUserResponseMessage(destinationPort)
      clientSocket.send(selectUserResponse.encode())

  def handleNeedhamSchroeder(self, userid_a, userid_b, nonce_a):
    session_key = ''
    response = []
    timestamp = self.encrypt("master", "TIME!!!")

    message_b = self.encrypt(userid_b, [session_key, userid_a])
    response = self.encrypt(userid_a, [session_key, userid_b, timestamp , nonce_a, message_b])

  def encrypt(self, userid, data):
    encrypt_key = self.clientKeys[userid]
    return data   # TODO: message encrypting




# Start server
Server()