#!/usr/bin/env python3
# simple setup
import sys
import os
# Add the ./Qdb of the project to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), './Qdb')))
from qdb import Qdb

# Qdb(["Qdb/src/mips32el_hello"], "rootfs/mips32el_linux", rr=True).interactive()
Qdb(["Qdb/src/arm32el_hello"], "/usr/arm-linux-gnueabihf").interactive()
# # Create new file in current directory called test.txt and write "Hello World" to it
# with open("/home/wdharri2/Documents/NCSU/CSC492/2024SpringTeam37-Batista/assembliss/test.txt", "w") as f:
#     f.write("Hello World\n")
# # Close the file
# f.close()
