#!/usr/bin/env python

""" 
Yang Yang
CS4740
PS1: Sockets Communication

Message classes for chat implmentation. GREETING is sent from client to server
in the initial communication. TEXT is a message sent from client to server.
INCOMING is a message sent from the server to all connected clients.
""" 

import json

class Message:
  def encode(self):
    # Returns the json format of all the instance variables of a message
    return json.dumps(self.__dict__)


class ListMessage(Message):
  def __init__(self, srcPort):
    self.messageType = "list"
    self.srcPort = srcPort

class ListResponseMessage(Message):
  def __init__(self, userList):
    self.messageType = "listResponse"
    self.userList = userList

class SelectUserMessage(Message):
  def __init__(self, username):
    self.messageType = "selectUser"
    self.username = username

class SelectUserResponseMessage(Message):
  def __init__(self, destinationPort, destinationUsername):
    self.messageType = "selectUserResponse"
    self.destinationPort = destinationPort
    self.destinationUsername = destinationUsername

class LoginMessage(Message):
  def __init__(self, srcPort, username, password):
    self.messageType = "login"
    self.srcPort = srcPort
    self.username = username
    self.password = password

class LoginResponseMessage(Message):
  def __init__(self, username, status):
    self.messageType = "loginResponse"
    self.username = username
    self.status = status

class ServerMessage(Message):
  def __init__(self, srcPort, message):
    self.messageType = "serverMessage"
    self.srcPort = srcPort
    self.message = message

class PrivateMessage(Message):
  def __init__(self, srcPort, destPort, message):
    self.messageType = "privateMessage"
    self.srcPort = srcPort
    self.destPort = destPort
    self.message = message

class EstablishPrivateMessage(Message):
  def __init__(self, srcPort, srcUsername):
    self.messageType = "establishPrivateMessage"
    self.srcPort = srcPort
    self.srcUsername = srcUsername

class PrivateMessageResponse(Message):
  def __init__(self, srcPort, destPort, message):
    self.messageType = "privateMessageResponse"
    self.srcPort = srcPort
    self.destPort = destPort
    self.message = message
