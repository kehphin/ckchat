#!/usr/bin/env python
import sys

# Christophe Leung
# Public Key Array Store
# December 10, 2015
# =================================================================================================
class jsonKeyImport():
    def __init__(self, fileinput):
        self.fileinput_path = fileinput
        self.clientPublicKey = None

    def run(self):
        public_key = self.file_read("array", self.fileinput_path)
        self.clientPublicKey = public_key
        print self.clientPublicKey
        print "bob"
        print "\n\n" + str(self.clientPublicKey).join("\n")
        print "\n\n" + "\n".join(self.clientPublicKey)
        print "\n\n" + self.file_read("string", self.fileinput_path)
        print "\n\n" + "".join(self.clientPublicKey)

    # =============================================================================================
    # Opens and reads a file
    def file_read(self, storeType, filepath):
        fileinput_content = None
        with open(filepath) as f:
            if storeType is "array":
                fileinput_content = f.readlines()
            elif storeType is "string":
                fileinput_content = f.read()
        return fileinput_content

    # =============================================================================================
    # Ends the program
    def end(self):
        sys.exit()

# =================================================================================================
# The main function
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 2:
        print "Incorrect arguments. Needs [filename]"
    else:
        filename = args[1]
        t = jsonKeyImport(filename)
        t.run()
        t.end()
