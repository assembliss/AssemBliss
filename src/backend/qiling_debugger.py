import re
from typing import Optional
from capstone import Cs, CsInsn
from qiling import Qiling
from unicorn import UC_ERR_READ_UNMAPPED
import unicorn


class QilingDebugger:
    """
    A class that manages the debugging of a Qiling instance.
    """

    interrupt = None
    disassembler_result = None
    insn_info = None
    regs = None
    current_state: dict = {'interrupt': str,
                           'line_number': int,
                           'insn': {'memory': int, 'instruction': str},
                           'regs': dict}
    breakpoints = []
    next_breakpoint: int
    breakpoints_enabled: bool

    def __init__(self, ql: Qiling, objdump: str):
        self.debugger_instance = None
        self.ql = ql
        self.objdump = objdump
        self.breakpoints_enabled = True
        self.interrupt = None

    def start(self, binary_file: str) -> None:
        """
        Starts the debugger with the given binary file.
        """
        if binary_file is None:
            raise ValueError("Binary file path is not provided.")

        self.interrupt = None
        # hook to code and interrupts before starting execution
        self.ql.clear_hooks()
        self.ql.hook_code(self.simple_disassembler,
                          user_data=self.ql.arch.disassembler)
        self.ql.hook_intr(self.inter_read)

        self.ql.run(count=1)
        objdump_output = self.parse_objdump_output(self.objdump)
        self.current_state = self.build_program_state_json(
            self.interrupt, self.insn_info, objdump_output
        )

    def set_breakpoint_address(self, address: int) -> None:
        """
        Sets a breakpoint at the specified address.
        """
        # self.breakpoints.append(address)
        # if self.next_breakpoint is None:
        #     self.next_breakpoint = address
        #     return
        # if (address < self.next_breakpoint and
        #         self.current_state['insn']['memory'] < address):
        #     self.next_breakpoint = address
        line_number = self.objdump.get(address)
        self.set_breakpoint_line(line_number)

    def set_breakpoint_line(self, line_number: int) -> None:
        """
        Sets a breakpoint at the specified line number.
        """
        if line_number is not None and line_number not in self.breakpoints:
            self.breakpoints.append(line_number)
            if self.next_breakpoint is None:
                self.next_breakpoint = line_number
                return
            if (line_number < self.next_breakpoint and
                    self.current_state['line_number'] < line_number):
                self.next_breakpoint = line_number

    def step(self) -> None:
        """
        Steps through the code.
        """
        self.interupt = None

        # read pc register to get next instruction address
        address = self.ql.arch.regs.read("pc")

        self.ql.run(begin=address, count=1)
        self.current_state = self.build_program_state_json(self.interupt,
                                                           self.insn_info,
                                                           self.objdump)

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

    def restart(self) -> None:
        """
        Restarts the debugger.
        """
        pass

    # Helper functions

    def simple_disassembler(self, ql: Qiling, address: int,
                            size: int, md: Cs) -> dict:
        """
        Disassembles the instruction at the specified address.
        """
        # Disassemble the memory part to remap it to what instruction happened.
        insn = self.disasm(address, True)
        m = ql.arch.regs.register_mapping
        regs = {}
        for k in m:
            regs[k] = ql.arch.regs.read(k)
        # add key and value to rtn
        rtn = insn.address, insn.mnemonic, insn.op_str, regs
        self.insn_info = insn
        self.regs = regs
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
                address = int(address_match.group(1), 16)
                address_to_line[address] = current_line_number

        return address_to_line

    def build_program_state_json(self, interrupt,
                                 insn_info: CsInsn, objdump: dict) -> dict:
        """
        Builds a JSON object containing the program state.
        """
        # {insn.address:#x}, {insn.mnemonic:s} {insn.op_str}
        # with open(INSN_INFO_FILE_NAME, 'r') as insnf:
        #     with open(REGS_INFO_FILE_NAME, 'r') as regsf:
        #  if interrupt has been detected send interrupt number else send na
        state = {}
        if interrupt is not None:
            state['interrupt'] = f'{interrupt}'
        else:
            state['interrupt'] = 'na'
        # get instruction information from param and read information to get
        # line number and info about instruction
        line_number = objdump.get(insn_info.address)
        state['line_number'] = line_number

        insn_map = {}
        insn_map['memory'] = insn_info.address
        instruct = f'{insn_info.mnemonic:s} {insn_info.op_str:s}'
        insn_map['instruction'] = instruct
        state['insn'] = insn_map

        state['regs'] = self.regs

        return state
    
    @property
    def cur_addr(self):
        """
        program counter of qiling instance
        """

        return self.ql.arch.regs.arch_pc
    
    @property
    def arch_insn_size(self):
        """
        Returns the architecture instruction size.
        """
        return 4

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
        interrupt reader prints interrupt number and sets interrupt number
        when qiling hooks to interrupt
        """
        self.interrupt = intno
