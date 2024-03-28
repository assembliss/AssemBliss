# simple setup
import sys
import os
# Add the ./Qdb of the project to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), './Qdb')))
from qdb import Qdb

Qdb(["Qdb/src/mips32el_hello"], "rootfs/mips32el_linux", rr=True).interactive()