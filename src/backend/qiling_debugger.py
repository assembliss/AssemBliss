from qiling import Qiling
from unicorn import UC_ERR_READ_UNMAPPED
import unicorn


class QilingDebugger:
    """
    A class that manages the debugging of a Qiling instance.
    """
    def __init__(self, ql: Qiling):
        self.debugger_instance = None
        self.ql = ql

    def start(self, binary_file: str) -> None:
        """
        Starts the debugger with the given binary file.
        """
        pass

    def set_breakpoint(self, address: int) -> None:
        """
        Sets a breakpoint at the specified address.
        """
        pass

    def step(self) -> None:
        """
        Steps through the code.
        """
        pass

    def get_registers(self) -> dict:
        """
        Returns the current state of the registers.
        """
        pass

    def stop(self) -> None:
        """
        Stops the debugger.
        """
        pass

    @property
    def cur_addr(self):
        """
        program counter of qiling instance
        """

        return self.ql.arch.regs.arch_pc

    def read_mem(self, address: int, size: int):
        """
        read data from memory of qiling instance
        """

        return self.ql.mem.read(address, size)

    def disasm(self, address: int, detail: bool = False) -> Optional[CsInsn]:
        """
        helper function for disassembling
        """

        md = self.ql.arch.disassembler
        md.detail = detail

        return next(md.disasm(self.read_insn(address), address), None)

    def try_read(self, address: int, size: int) -> Optional[bytes]:
        """
        try to read data from ql.mem
        """

        result = None
        err_msg = ""
        try:
            result = self.read_mem(address, size)

        except unicorn.unicorn.UcError as err:
            if err.errno == UC_ERR_READ_UNMAPPED:  # Invalid memory read
                # (UC_ERR_READ_UNMAPPED)
                err_msg = f"Can not access memory at address \
                    0x{address:08x}"

        except:
            pass

        return (result, err_msg)
   
    def read_insn(self, address: int) -> bytes:
        """
        read instruction depending on current operating mode
        """

        pass