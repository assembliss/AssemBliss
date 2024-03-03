# simple setup
from qdb import Qdb

Qdb(["src/hello.s"], "rootfs/mipsel-linux-gnu", rr=True).interactive()