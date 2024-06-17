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
    #TODO: fix property decorators
    @property   
    def get_registers(self) -> dict:
        """
        Returns the current state of the registers.
        """
        return self.regs

    @property
    def cur_addr(self):
        """
        program counter of qiling instance
        This is the address of the next instruction to be executed.
        """

        return self.ql.arch.regs.arch_pc

    @property
    def arch_insn_size(self):
        """
        Returns the architecture instruction size.
        """
        return 4

    @property
    def get_current_state(self) -> dict:
        """
        Returns the current state of the debugger.
        """
        return self.current_state
    
    def __init__(self, ql: Qiling, objdump: str):
        self.debugger_instance = None
        self.ql = ql
        self.objdump: dict = self.parse_objdump_output(objdump)
        self.interrupt = None
        self.disassembler_result = None
        self.insn_info: CsInsn = None
        self.regs: dict = {}
        instruction = self.disasm(self.ql.loader.entry_point, True)
        self.current_state: dict = {
            'interrupt': str,
            'line_number': self.objdump.get(self.ql.loader.entry_point),
            'insn': {
                'memory': self.ql.loader.entry_point,
                'instruction': instruction.mnemonic + " " + instruction.op_str
            },
            'regs': dict}

        # TODO: implement replacing instruction with breakpoint instruction BRK
        self.breakpoints: dict = {}
        self.breakpoints_enabled: bool = True

    def start(self, binary_file: str) -> None:
        """
        Starts the debugger with the given binary file.
        """
        if binary_file is None:
            raise ValueError("Binary file path is not provided.")

        self.interrupt = None
        # hook to interrupts before starting execution
        self.ql.clear_hooks()
        self.ql.hook_intr(self.inter_read)  # used to set interrupt number
        self.run()

    def set_breakpoint_address(self, address: int) -> None:
        """
        Sets a breakpoint at the specified address.
        """
        # Read the original 4-byte instruction
        original_instruction = self.try_read(address, 4)[0]
        # original_instruction = bytearray(self.ql.mem.read(address, 4))
        brk_instruction = b'\x00\x00\x20\xd4'  # brk #0
        # TODO: find out if I need to differentiate brk instructions #0, #1, etc.
        # Write the brk instruction to the address
        self.ql.mem.write(address, brk_instruction)
        # Save the original instruction
        self.breakpoints[address] = bytes(original_instruction)

    def set_breakpoint_line(self, line_number: int,
                            address: Optional[int]) -> None:
        """
        Sets a breakpoint at the specified line number.
        """
        if address is None:
            found = False
            original_line_number = line_number
            while not found:
                for addr, line in self.objdump.items():
                    if line == line_number:
                        address = addr
                        found = True
                        break
                if not found:
                    line_number += 1
                    # Add a stopping condition to avoid an infinite loop
                    if line_number > max(self.objdump.values()):
                        raise ValueError("No address found for line number "
                                         + f"{original_line_number} or "
                                         + "any subsequent line.")
        self.set_breakpoint_address(address)
    
    def remove_breakpoint(self, line_number: Optional[int], address: Optional[int]) -> None:
        """
        Removes a breakpoint at the specified line number.
        """
        if line_number is None and address is None:
            raise ValueError("Line number or address must be provided.")
        # address will take precedence
        if line_number is not None and address is None:
            found = False
            while not found:
                for addr, line in self.objdump.items():
                    if line == line_number:
                        address = addr
                        found = True
                        break
                if not found:
                    line_number += 1
                    # Add a stopping condition to avoid an infinite loop
                    if line_number > max(self.objdump.values()):
                        raise ValueError("No address found for line number "
                                         + f"{line_number} or "
                                         + "any subsequent line.")
        if address in self.breakpoints:
            # restore original instruction
            self.ql.mem.write(address, self.breakpoints[address])
            del self.breakpoints[address]  # remove breakpoint from list

    def step(self, steps: int = 1) -> None:
        """
        Steps through the code.
        """
        self.interrupt = None

        # read pc register to get next instruction address
        address = self.cur_addr

        self.run(begin=address, count=steps)  # NOTE: bug with qiling
        # where hook is not called back after running in address range

    def cont(self) -> None:
        """
        Continues running the code.
        """
        self.interrupt = None
        
        # read pc register to get next instruction address
        address = self.cur_addr
        
        self.run(begin=address, count=None)

    def stop(self) -> dict:
        """
        Stops the debugger.
        TODO: figure out if ql.stop ends execution or just pauses it.
            For now, here is implementation pausing it.
        """
        self.ql.stop()
        # if this paused execution, then we need to update the current state
        # TODO: test that the current state is updated by calling stop mid loop 
        # that updates a register value every iteration

        return self.update_current_state()

    def restart(self, objdump: Optional[str]) -> None:
        """
        Restarts the debugger.
        """
        self.ql = Qiling([self.ql.path],
                         rootfs=self.ql.rootfs,
                         verbose=self.ql.verbose)
        self.debugger_instance = None
        if objdump is not None:
            self.objdump = self.parse_objdump_output(objdump)
        # self.breakpoints_enabled = True
        self.interrupt = None
        self.disassembler_result = None
        self.insn_info: CsInsn = None
        self.regs: dict = {}
        self.current_state: dict = {'interrupt': str,
                                    'line_number': int,
                                    'insn': {'memory': int,
                                             'instruction': str},
                                    'regs': dict}
        # self.breakpoints: list = []
        # self.breakpoints_enabled: bool
        self.start(self.ql.path)

    # Helper functions

    def run(self, begin: Optional[int] = None,
            end: Optional[int] = None, count: int = 1,
            timeout: int = 10000) -> None:
        """
        Runs the debugger for the specified number of instructions.
        Updates the current state of the debugger through hook and
        reading registers.
        """
        if begin is None:
            if end is not None:  # end cannot be specified without begin
                raise ValueError("End cannot be specified without begin.")
            self.ql.run(count=count, timeout=timeout)  # run for count ins
        elif end is None:  # run from beginning address
            if count is None:  # continue running until end of code or brkpnt
                self.ql.run(begin=begin, timeout=timeout)
            else:  # run for count instructions
                self.ql.run(begin=begin, count=count, timeout=timeout)
        else:  # run from beginning address to end address
            self.ql.run(begin=begin, end=end, timeout=timeout)

        # Update the registers after the instruction is executed
        m = self.ql.arch.regs.register_mapping
        regs = {}
        for k in m:
            regs[k] = self.ql.arch.regs.read(k)
        self.regs = regs

        # Update the current state
        self.simple_disassembler(
            self.ql, self.cur_addr,
            self.arch_insn_size, md=None)
        self.update_current_state()

    def simple_disassembler(self, ql: Qiling, address: int,
                            size: int, md: Cs) -> dict:
        """
        Disassembles the instruction at the specified address.
        """
        # Disassemble the memory part to remap it to what instruction happened.
        insn = self.disasm(address, True)

        # add key and value to rtn
        rtn = insn.address, insn.mnemonic, insn.op_str
        self.insn_info = insn
        # self.regs = regs
        return rtn  # NOTE: if {insn.mnemonic:s} {insn.op_str} == udf #0 stop

    def breakpoint_hit(self) -> bool:
        """
        Handles the breakpoint hit event.
        """
        state = self.stop()
        print("Breakpoint hit at line " + str(state.get('line_number'))
              + f" {{{hex(state.get('insn').get('memory'))}}}")
        # restore original instruction
        self.ql.mem.write(self.cur_addr, self.breakpoints[self.cur_addr])

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

    def update_current_state(self) -> dict:
        """
        Builds a JSON object containing the program state.
        This is necessary to send the program state to the frontend.
        """
        # {insn.address:#x}, {insn.mnemonic:s} {insn.op_str}
        # with open(INSN_INFO_FILE_NAME, 'r') as insnf:
        #     with open(REGS_INFO_FILE_NAME, 'r') as regsf:
        #  if interrupt has been detected send interrupt number else send na
        state = {}
        if self.interrupt is not None:
            state['interrupt'] = self.interrupt
        else:
            state['interrupt'] = 'na'
        # get instruction information from param and read information to get
        # line number and info about instruction
        line_number = self.objdump.get(self.cur_addr)
        state['line_number'] = line_number

        insn_map = {}
        insn_map['memory'] = self.insn_info.address
        instruct = f'{self.insn_info.mnemonic:s} {self.insn_info.op_str:s}'
        insn_map['instruction'] = instruct
        state['insn'] = insn_map

        state['regs'] = self.get_registers

        self.current_state = state
        return state

    def toggle_breakpoints(self) -> None:
        """
        Toggles the breakpoints on and off.
        """
        self.breakpoints_enabled = not self.breakpoints_enabled

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

    def inter_read(self, ql: Qiling, intno: Optional[int]):
        """
        interrupt reader prints interrupt number and sets interrupt number
        when qiling hooks to interrupt
        TODO: figure out if this can be retrieved after instruction is executed
        """
        if intno is not None:
            self.interrupt = intno
        if self.cur_addr in self.breakpoints:
            # if intno == 7:  # interrupt number for BRK instruction TODO: find out if this is correct
            self.breakpoint_hit()
        #FIXME: self.curr_addr is not updated after this is called from BRK instruction