import re
from typing import Optional
from capstone import Cs, CsInsn
from qiling import Qiling
from unicorn import UC_ERR_READ_UNMAPPED
import unicorn

class QilingDebugger:

    interupt = None
    arch_insn_size = 4

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
        if (binary_file is None):
            raise ValueError("Binary file path is not provided.")

        self.interupt = None
        # hook to code and interupts before starting execution
        self.ql.clear_hooks()
        self.ql.hook_code(self.simple_disassembler,
                          user_data=self.ql.arch.disassembler)
        self.ql.hook_intr(self.inter_read)

        self.ql.run(count=1)
                
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

    # Helper functions

    def simple_disassembler(self, ql: Qiling, address: int,
                            size: int, md: Cs) -> dict:
        """
        Disassembles the instruction at the specified address.
        """
        rtn = {}
        # Disassemble the memory part to remap it to what instruction happened.
        insn = self.disasm(address, True)
        m = ql.arch.regs.register_mapping
        regs = {}
        for k in m:
            regs[k] = ql.arch.regs.read(k)
        # add key and value to rtn
        rtn.update(
            {f"{insn.address:#x}, {insn.mnemonic:s} {insn.op_str}": regs})
        return rtn  # NOTE: if {insn.mnemonic:s} {insn.op_str} == udf #0 stop

    def parse_objdump_output(self, output: str) -> dict:
        """
        Parses the output of the objdump command and extracts the mapping 
        between memory addresses and source code line numbers.

        Args:
            output (str): The output of the objdump command.

        Returns:
            dict: A dictionary mapping memory addresses to 
            source code line numbers.
        """
        address_to_line = {}
        current_line_number = None

        # Regex pattern to match source file lines with
        # .s, .arm, and .asm extensions, case insensitive
        source_line_pattern = re.compile(r'.*\.(s|arm|asm):(\d+)',
                                         re.IGNORECASE)

        for line in output.splitlines():
            # Match lines that contain source file and line number
            source_line_match = source_line_pattern.match(line)
            if source_line_match:
                current_line_number = int(source_line_match.group(2))

            # Match lines that contain memory addresses
            address_match = re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]+\s+.*',
                                     line)
            if address_match and current_line_number is not None:
                address = address_match.group(1)
                address_to_line[address] = current_line_number

        return address_to_line

    def build_program_state_JSON(self, interupt) -> str:
        """
        Builds a JSON object containing the program state.
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

        finally:
            if (result is None and err_msg == ""):
                err_msg = f"Unknown error occurred while reading memory at \
                    address 0x{address:08x}"

        return (result, err_msg)

    def read_insn(self, address: int) -> bytes:
        """
        read instruction
        """
        return self.read_mem(address, self.arch_insn_size)

    def inter_read(self, intno):
        """
        interupt reader prints interupt number and sets interupt number
        when qiling hooks to interupt
        """
        self.interupt = intno
