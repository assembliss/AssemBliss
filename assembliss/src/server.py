from qiling import *
from qiling.const import QL_VERBOSE

def test_gdb(path, rootfs):
    print("Running GDB server at localhost:9999")
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.OFF)
    print("GDB server is running at localhost:9999")
    # Enable debugger to listen at localhost address, default port 9999
    ql.debugger = True
    
    # You can also customize address & port or type of debugging server
    # ql.debugger= ":9999"  # GDB server listens to 0.0.0.0:9999
    # ql.debugger = "127.0.0.1:9999"  # GDB server listens to 127.0.0.1:9999
    # ql.debugger = "gdb:127.0.0.1:9999"  # GDB server listens to 127.0.0.1:9999
    # ql.debugger = "idapro:127.0.0.1:9999"  # IDA pro server listens to 127.0.0.1:9999

    ql.run()  
    
if __name__ == "__main__":
    # test_gdb([<path to binary>], [<path to rootfs>)
    # binary is what you want to run in the Qiling
    # rootfs is the root file system for the Qiling
    # root file system is the directory where the Qiling will look for the files
    test_gdb(["../rootfs/x8664_linux/bin/x8664_hello_static"], "../rootfs/x8664_linux")
    # TODO eventually change to arm