#!/usr/bin/env python
import sys
import hashlib, uuid

import os, ast


# Christophe Leung
# Password Storing / Authenticating
# December 10, 2015
# =================================================================================================
class password():
  def __init__(self):
    self.debugMode = True
    self.writeMode = False
    self.password_db = {}
    self.database_path = "database"


  # Runs the program
  def run(self):
    if self.writeMode:
      # Create Username/Password Pairs
      self.password_create("chris", "1234567890")
      self.password_create("kevin", "qwertyuiop")
      self.password_create("alice", "asdfghjkl")
      self.password_create("bobby", "zxcvbnm,")
      self.file_write(self.database_path, str(self.password_db))
    else:
      # Import Password Database
      self.password_db = ast.literal_eval(self.file_read("string", self.database_path))

      # Validate Supplied Username/Password Pairs
      self.debug(str(self.password_validate("chris", "123")))
      self.debug(str(self.password_validate("chris", "12345678")))
      self.debug(str(self.password_validate("kevin", "qwertyuiop")))


  # Ends the program
  def end(self):
      sys.exit()

  # =============================================================================================
  # Enables debug messages
  def debug(self, text):
    if self.debugMode:
      print "[DEBUG] " + text

  # Opens and reads a file
  def file_read(self, storeType, filepath):
    self.debug("reading from input file...")
    fileinput_content = None
    with open(filepath) as f:
      if storeType is "array":
        fileinput_content = f.readlines()
      elif storeType is "string":
        fileinput_content = f.read()
    return fileinput_content

  # Opens and appends to the designated output file
  def file_write(self, fileoutput_path, contents):
    self.debug("writing to output file...")
    if os.path.isfile(fileoutput_path):
      print "\"" + fileoutput_path + "\" already exists...overwriting..."
      os.remove(fileoutput_path)
    with open(fileoutput_path, "a") as f:
      f.write(contents)


  # =============================================================================================
  # Create a username/hashed-password entry for the database
  def password_create(self, username, password):
    self.debug("creating password...")
    if(len(password) >= 8):
      salt = uuid.uuid4().hex
      password_hashed = hashlib.sha512(password + salt).hexdigest()
      salt_pwhashed = (salt, password_hashed)
      self.password_db[username] = salt_pwhashed
      return salt_pwhashed
    else:
      print "password must be at least 8 characters long."
      print "password creation aborted."
      self.end()

  # Validate a password
  def password_validate(self, username, password_client):
    self.debug("validating password...")
    salt_retrieved = self.password_db[username][0]
    password_retrieved = self.password_db[username][1]
    password_client_hashed = hashlib.sha512(password_client + salt_retrieved).hexdigest()
    return password_client_hashed == password_retrieved


# =================================================================================================
# The main function
if __name__ == "__main__":
  t = password()
  t.run()
  t.end()
