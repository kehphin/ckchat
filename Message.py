#!/usr/bin/env python


import json

class Message:
  def encode(self):
    # Returns the json format of all the instance variables of a message
    return json.dumps(self.__dict__)

class ListMessage(Message):
  def __init__(self, srcPort, username):
    self.messageType = "list"
    self.srcPort = srcPort
    self.username = username

class ListResponseMessage(Message):
  def __init__(self, userList):
    self.messageType = "listResponse"
    self.userList = userList

class SelectUserMessage(Message):
  def __init__(self, fromUser, toUser, nonce):
    self.messageType = "selectUser"
    self.fromUser = fromUser
    self.toUser = toUser
    self.nonce = nonce

class SelectUserResponseMessage(Message):
  def __init__(self, toUser, toUserPubKey="", toUserPort="", sessionKey="", nonceReturned="", timestamp="", forwardBlock=""):
    self.messageType = "selectUserResponse"
    self.toUser = toUser
    self.toUserPubKey = toUserPubKey
    self.toUserPort = toUserPort
    self.sessionKey = sessionKey
    self.nonceReturned = nonceReturned
    self.timestamp = timestamp
    self.forwardBlock = forwardBlock

    #NA, KA, TA }KC
class LoginAuth(Message):
  def __init__(self, srcPort, nonce, timestamp, clientPublicKey):
    self.messageType = "loginAuth"
    self.srcPort = srcPort
    self.nonce = nonce
    self.timestamp = timestamp
    self.clientPublicKey = clientPublicKey

class LoginAuthResponse(Message):
  def __init__(self, nonce, timestamp):
    self.messageType = "loginAuthResponse"
    self.nonce = nonce
    self.timestamp = timestamp

class LoginMessage(Message):
  def __init__(self, srcPort, username, password, clientPublicKey):
    self.messageType = "login"
    self.srcPort = srcPort
    self.username = username
    self.password = password
    self.clientPublicKey = clientPublicKey

class LoginResponseMessage(Message):
  def __init__(self, username, status):
    self.messageType = "loginResponse"
    self.username = username
    self.status = status

class PrivateMessage(Message):
  def __init__(self, srcPort, srcUsername, destPort, message):
    self.messageType = "privateMessage"
    self.srcPort = srcPort
    self.srcUsername = srcUsername
    self.destPort = destPort
    self.message = message

class PrivateEncryptedSubmessage(Message):
  def __init__(self, message, username):
    self.messageType = "privateEncryptedSubmessage"
    self.message = message
    self.username = username

class EstablishPrivateMessage(Message):
  def __init__(self, srcPort, srcUsername, srcPublicKey, forwardBlock, nonce):
    self.messageType = "establishPrivateMessage"
    self.srcPort = srcPort
    self.srcUsername = srcUsername
    self.srcPublicKey = srcPublicKey
    self.forwardBlock = forwardBlock
    self.nonce = nonce

class EstablishPrivateMessageResponse(Message):
  def __init__(self, username, nonce):
    self.messageType = "establishPrivateMessageResponse"
    self.username = username
    self.nonce = nonce

class PrivateMessageResponse(Message):
  def __init__(self, srcPort, destPort, message):
    self.messageType = "privateMessageResponse"
    self.srcPort = srcPort
    self.destPort = destPort
    self.message = message

class LogoutMessage(Message):
  def __init__(self, username):
    self.messageType = "logoutMessage"
    self.username = username

class NeedhamSchroeder_Auth3(Message):
  def __init__(self, destinationUsername, sessionKey, serverTimestamp):
    self.messageType = "NeedhamSchroeder_Auth3"
    self.destinationUsername = destinationUsername
    self.sessionKey = sessionKey
    self.serverTimestamp = serverTimestamp