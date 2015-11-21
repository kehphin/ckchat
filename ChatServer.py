#!/usr/bin/env python 

""" 
Yang Yang
CS4740
PS1: Sockets Communication

A chat server implemented with threads. Listens for GREETING and TEXT messages and
broadcasts INCOMING messages to all clients connected to the server.

Runs with the arguments: -sp <port_number>
""" 

import select 
import socket 
import sys 
import threading 
import json

from Message import Incoming

# Class for server
class Server: 
  def __init__(self, port): 
    self.host = '' 
    self.port = port
    self.backlog = 5 
    self.size = 1024 
    self.server = None 
    self.threads = [] 

  def run(self): 
    self.open_socket() 
    running = 1 
    while running: 
      inputready, outputready, exceptready = select.select([self.server, sys.stdin], [], []) 
      for action in inputready: 
        if action == self.server: 
          # New client socket connection to server; create new thread
          c = ClientThread(self.server.accept()) 
          c.start() 
          self.threads.append(c) 
        # Enter any input to stop server
        elif action == sys.stdin:
          running = 0 

    self.shutdown()

  # Opens the server socket and starts to listen for incoming connections
  def open_socket(self): 
    try: 
      self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
      self.server.bind((self.host, self.port)) 
      self.server.listen(5) 
    except socket.error, (value, message): 
      if self.server: 
        self.server.close() 

      print "Could not open socket: " + message 
      sys.exit(1) 

  # Closes all active threads and shuts down the server.
  def shutdown(self):
    print "Shutting down server."
    self.server.close() 
    for c in self.threads: 
      c.join() 

# Class for client threads
class ClientThread(threading.Thread): 
  def __init__(self,(client,address)): 
    threading.Thread.__init__(self) 
    self.client = client 
    self.address = address 
    self.size = 1024
    self.status = "inactive" # Start socket thread as inactive, set as active after receiving GREETING

  def run(self): 
    running = 1 
    while running: 
      try: 
        # Get and parse the json data obtained from the client associated with the thread
        data = self.client.recv(self.size) 
        jsonMessage = json.loads(data)

        # Set thread and connection as active upon receiving greeting message
        if jsonMessage['messageType'] == 'greeting': 
          self.status = "active"
        # Take the TEXT message from client and rebroadcast to all clients as an INCOMING message
        elif jsonMessage['messageType'] == 'text':
          self.sendIncomingMessage(jsonMessage['message'])

      except ValueError:
        self.closeThread()
        running = 0 

  # Broadcast INCOMING message to all threads/ socket connections that are active
  def sendIncomingMessage(self, message):
    for thread in s.threads:
      if thread.status == 'active':
        try: 
          incoming = Incoming(message, self.address[0], self.address[1])
          thread.client.send(incoming.encode())

        except socket.error, (value, message): 
          print 'Could not send message to <{0}:{1}>'.format(thread.address[0], thread.address[1])
          self.closeThread()

  # Set thread as inactive and close it
  def closeThread(self):
    self.status = "inactive"
    self.client.close() 


# Parse arguments for port and instantiate Server
port = None
if (len(sys.argv) == 3):
  if sys.argv[1] == '-sp':
    try:
      port = int(sys.argv[2])
    except ValueError:
      print("Server must be run with the arguments: -sp <port_number>")
if port is None:
  print("Server must be run with the arguments: -sp <port_number>")
else:
  s = Server(port) 
  s.run()
