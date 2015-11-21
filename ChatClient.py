#!/usr/bin/env python

""" 
Yang Yang
CS4740
PS1: Sockets Communication

A chat client implemented in Python. Sends a GREETING message upon opening
the socket connection with the server, and sends TEXT messages upon user input.
Also listens to INCOMING message pushes from the server that are send by other clients.

Runs with the arguments: -sip <server_ip> -sp <port_number>
""" 

import select 
import socket
import sys
import json

from Message import Greeting
from Message import Text
from Message import Incoming

host = None
port = None
size = 1024

# Parse arguments for host, port and connect to host server
if (len(sys.argv) == 5):
  if sys.argv[1] == '-sip' and sys.argv[3] == '-sp':
    try:
      host = sys.argv[2]
      port = int(sys.argv[4])
    except ValueError:
      print("Client must be run with the arguments: -sip <server_ip> -sp <port_number>")
      sys.exit(1)
if port is None or host is None:
  print("Client must be run with the arguments: -sip <server_ip> -sp <port_number>")
  sys.exit(1)

# Create socket and connect to server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))

# Send initial Greeting message to tell server that the socket is active
greeting = Greeting()
s.send(greeting.encode())

while 1:
  inputready,outputready,exceptready = select.select([s,sys.stdin],[],[])
  for action in inputready:
    # Read INCOMING message pushed by server and display to user's command prompt
    if action == s:
      data = s.recv(size)
      jsonMessage = json.loads(data)
      print '<- <From {0}:{1}>: {2}'.format(jsonMessage['ip'], jsonMessage['port'], jsonMessage['message'])

    # Send user's message as a TEXT message to the server
    elif action == sys.stdin:
      # Some command line manipulation to get messages to display properly
      PREVIOUS_LINE = '\x1b[1A'
      DELETE_LINE = '\x1b[2K'
      print(PREVIOUS_LINE + DELETE_LINE + PREVIOUS_LINE)

      line = sys.stdin.readline()
      # If user enters nothing, we take it as the command to shut down the client
      if line == '\n':
        break

      # Strip new line of user's message and send to server as a TEXT encoded in json
      text = Text(line.rstrip())
      s.send(text.encode())

# Close the socket
s.close()