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

    def __init__(self, ql: Qiling, objdump: str):
        self.debugger_instance = None
        self.ql = ql
        self.objdump: dict = self.parse_objdump_output(objdump)
        self.interrupt = None
        self.next_breakpoint: int = 0
        self.disassembler_result = None
        self.insn_info: CsInsn = None
        self.regs: dict = {}
        self.current_state: dict = {
            'interrupt': str,
            'line_number': int,
            'insn': {
                'memory': int,
                'instruction': str
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
        # hook to code and interrupts before starting execution
        self.ql.clear_hooks()
        self.ql.hook_code(self.simple_disassembler,
                          user_data=self.ql.arch.disassembler)
        self.ql.hook_intr(self.inter_read)  # used to set interrupt number
        self.ql.run(count=1)
        self.current_state = self.build_program_state_json(
            self.interrupt, self.insn_info, self.objdump
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
        self.set_breakpoint_line(line_number, address)

    def set_breakpoint_line(self, line_number: int,
                            address: Optional[int]) -> None:
        """
        Sets a breakpoint at the specified line number.
        """
        if line_number not in self.breakpoints:
            if address is not None:
                self.breakpoints[line_number] = address
                # TODO: verify if there are any issues with incorrect address
            else:
                # get address from objdump
                for key, value in self.objdump.items():
                    if value == line_number:
                        self.breakpoints[line_number] = key
                        break
        if self.next_breakpoint is None or self.next_breakpoint == 0:
            self.next_breakpoint = line_number
        elif (line_number < self.next_breakpoint and
                self.current_state['line_number'] < line_number):
            self.next_breakpoint = line_number

    def step(self, steps: int = 1) -> None:
        """
        Steps through the code.
        """
        self.interrupt = None

        # read pc register to get next instruction address
        address = self.ql.arch.regs.read("pc")

        self.ql.run(begin=address, count=steps)  # NOTE: bug with qiling
        # where hook is not called back after running in address range
        self.update_current_state()

    def update_current_state(self) -> None:
        self.current_state = self.build_program_state_json(self.interrupt,
                                                           self.insn_info,
                                                           self.objdump)
        if (
            len(self.breakpoints) > 0 and
            self.current_state['line_number'] >= self.next_breakpoint
        ):
            # find next breakpoint from breakpoints list and set it
            for point in self.breakpoints:
                if point > self.current_state['line_number']:
                    self.next_breakpoint = point
                    return

    def get_registers(self) -> dict:
        """
        Returns the current state of the registers.
        """
        return self.regs

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
        self.current_state = self.build_program_state_json(self.interrupt,
                                                           self.insn_info,
                                                           self.objdump)
        return self.current_state
    
    def cont(self, stop_addr: Optional[int]) -> None:
        """
        Continues the execution of the program.
        """
        address = self.ql.arch.regs.read("pc")
        # FIXME: I would prefer to use the following but qiling has a bug where
        # this execution format never returns or the hook is never called back
        # in following run calls
        # self.ql.run(begin=address, end=end_addr)
        # This issue is solved by using self.ql.clear_hooks() before running
        # But this causes another issue with svc instructions
        # where the emulated program crashes
        
        # read pc register to get next instruction address
        if stop_addr is not None:
            #FIXME: add check for breakpoint hit
            while True:  # emulate do while loop
                self.ql.run(begin=address, count=1)  # using this avoids ql bug
                last_address = address
                address = self.ql.arch.regs.read("pc")  # get next inst address
                self.update_current_state()
                if address == stop_addr:
                    break
                if last_address == address:  # if address is not updated
                    # (avoid infinite loop)
                    break
            #  FIXME: use this when qiling bug mentioned above is fixed
            # self.ql.run(begin=address, end=stop_addr)
            self.update_current_state()
        elif (self.breakpoints_enabled and self.next_breakpoint is not None
              and self.current_state['line_number'] < self.next_breakpoint):
            #TODO: remove next breakpoint variable because this needs to be
            # determined after each step because of jumps. Just check if the 
            # current line number is in the breakpoints list
        else:
            stop = list(self.objdump.keys())[-1]
            while self.current_state['insn']['memory'] <= stop:
                self.ql.run(begin=address, count=1)
                last_address = address
                address = self.ql.arch.regs.read("pc")
                self.update_current_state()
                if last_address == address:  # if address is not updated
                    break

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
        if len(self.breakpoints) > 0:
            self.next_breakpoint = sorted(self.breakpoints.keys())[0]
        else:
            self.next_breakpoint: int = 0
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

    def build_program_state_json(self, interrupt: int,
                                 insn_info: CsInsn, objdump: dict) -> dict:
        """
        Builds a JSON object containing the program state.
        This is necessary to send the program state to the frontend.
        """
        # {insn.address:#x}, {insn.mnemonic:s} {insn.op_str}
        # with open(INSN_INFO_FILE_NAME, 'r') as insnf:
        #     with open(REGS_INFO_FILE_NAME, 'r') as regsf:
        #  if interrupt has been detected send interrupt number else send na
        state = {}
        if interrupt is not None:
            state['interrupt'] = interrupt
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

        state['regs'] = self.get_registers()

        return state

    def toggle_breakpoints(self) -> None:
        """
        Toggles the breakpoints on and off.
        """
        self.breakpoints_enabled = not self.breakpoints_enabled

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

    def inter_read(self, ql: Qiling, intno: Optional[int]):
        """
        interrupt reader prints interrupt number and sets interrupt number
        when qiling hooks to interrupt
        """
        if intno is not None:
            self.interrupt = intno
