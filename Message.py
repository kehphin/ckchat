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

class Greeting(Message):
  def __init__(self):
    self.messageType = "greeting"

class Text(Message):
  def __init__(self, message):
    self.messageType = "text"
    self.message = message
    
class Incoming(Message):
  def __init__(self, message, ip, port):
    self.messageType = "incoming"
    self.message = message
    self.ip = ip
    self.port = port