# Copyright 2024 Willie D. Harris, Jr., Dr. Caio Batista de Melo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
This module provides a QilingDebugger class for debugging a Qiling instance
running ARMv8 assembly code.

The QilingDebugger class provides methods for setting breakpoints, stepping,
continuing, and stopping the execution of ARMv8 assembly code.
"""
import re
from typing import Optional
from capstone import CsInsn
from qiling import Qiling
from unicorn import UC_ERR_READ_UNMAPPED
import unicorn


class QilingDebugger:
    """
    A class that manages the debugging of a Qiling instance.
    """

    @property
    def get_registers(self) -> dict:
        """
        Returns the current state of the registers.
        """
        return self._regs

    @property
    def cur_addr(self):
        """
        program counter of qiling instance
        This is the address of the next instruction to be executed.
        """

        return self._ql.arch.regs.arch_pc

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
        return self._current_state

    @property
    def qiling_instance(self) -> Qiling:
        """
        Returns the Qiling instance.
        """
        return self._ql

    @property
    def breakpoints(self) -> dict:
        """
        Returns the breakpoints.
        """
        return self._breakpoints

    @property
    def running(self) -> bool:
        """
        Returns whether the debugger is running.
        """
        return self._running

    def __init__(self, ql: Qiling, objdump: str):
        self._ql = ql
        self.objdump: dict = self.parse_objdump_output(objdump)
        self._interrupt = None
        self._insn_info: CsInsn = None
        self._regs: dict = {}
        instruction = self.disasm(self._ql.loader.entry_point, True)
        self._current_state: dict = {
            'interrupt': str,
            'line_number': self.objdump.get(self._ql.loader.entry_point),
            'insn': {
                'memory': self._ql.loader.entry_point,
                'instruction': instruction.mnemonic + " " + instruction.op_str
            },
            'regs': dict
        }
        self._breakpoints: dict = {}
        self.breakpoints_enabled: bool = True
        self._running: bool = False
        # hook to interrupts before starting execution
        # self._ql.clear_hooks()
        self._ql.hook_intr(self._inter_read)  # used to set interrupt number
        self._orignal_state = self.qiling_instance.save()

    def start(self, binary_file: str) -> None:
        """
        Starts the debugger with the given binary file.
        """
        if binary_file is None:
            raise ValueError("Binary file path is not provided.")

        self._interrupt = None

        self._running = True
        self._run()

    def set_breakpoint_address(self, address: int) -> None:
        """
        Sets a breakpoint at the specified address.
        """
        # Read the original 4-byte instruction
        original_instruction = self.try_read(address, 4)[0]

        mnemonic = b'\x20\xd4'
        immediate = len(self.breakpoints)
        # convert immediate to bytes
        immediate_bytes = immediate.to_bytes(2, byteorder='little')
        brk_instruction = immediate_bytes + mnemonic

        # Write the brk instruction to the address
        self._ql.mem.write(address, brk_instruction)
        # Save the original instruction
        self._breakpoints[address] = bytes(original_instruction)

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

    def remove_breakpoint(self, line_number: Optional[int],
                          address: Optional[int]) -> None:
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
        if address in self._breakpoints:
            # restore original instruction
            self.qiling_instance.mem.write(address, self._breakpoints[address])
            del self._breakpoints[address]  # remove breakpoint from list

    def step(self, steps: int = 1) -> None:
        """
        Steps through the code.
        """
        if not self.running:
            print("The program is not being run.")
            return
        self._interrupt = None

        # read pc register to get next instruction address
        address = self.cur_addr

        self._run(begin=address, count=steps)

    def cont(self) -> None:
        """
        Continues running the code.
        """
        if not self.running:
            print("The program is not being run.")
            return
        self._interrupt = None

        # read pc register to get next instruction address
        address = self.cur_addr

        self._run(begin=address, count=None)

    def stop(self) -> dict:
        """
        Stops the debugger.
        """
        self.qiling_instance.emu_stop()

        return self.update_current_state()

    def restart(self, objdump: Optional[str]) -> None:
        """
        Restarts the debugger.
        """
        self.stop()
        self._ql.restore(self._orignal_state)

        if objdump is not None:
            self.objdump = self.parse_objdump_output(objdump)

        self._interrupt = None
        self._insn_info: CsInsn = None
        self._regs: dict = {}
        instruction = self.disasm(
            self.qiling_instance.loader.entry_point, True)
        self._current_state: dict = {
            'interrupt': str,
            'line_number': self.objdump.get(
                self.qiling_instance.loader.entry_point),
            'insn': {
                'memory': self._ql.loader.entry_point,
                'instruction': instruction.mnemonic + " " + instruction.op_str
            },
            'regs': dict
        }
        if self.breakpoints_enabled:
            for address in self._breakpoints:
                self.set_breakpoint_address(address)
        self._running = False

    def toggle_breakpoints(self) -> None:
        """
        Toggles the breakpoints on and off.
        """
        self.breakpoints_enabled = not self.breakpoints_enabled

        if self.breakpoints_enabled:
            for address in self._breakpoints:
                # read the original 4-byte instruction
                original_instruction = self.try_read(address, 4)[0]
                mnemonic = b'\x20\xd4'
                immediate = len(self._breakpoints)
                # convert immediate to bytes
                immediate_bytes = immediate.to_bytes(2, byteorder='little')
                brk_instruction = immediate_bytes + mnemonic
                # write the brk instruction to the address
                self._ql.mem.write(address, brk_instruction)
                # save the original instruction
                self._breakpoints[address] = bytes(original_instruction)
        else:
            for address, instruction in self._breakpoints.items():
                # restore original instruction
                self._ql.mem.write(address, instruction)

    # Helper functions

    def _run(self, begin: Optional[int] = None,
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
            self._ql.emu_start(begin=self._ql.loader.entry_point,
                               end=0, count=count, timeout=timeout)
        elif end is None:  # run from beginning address
            if count is None:  # continue running until end of code or brkpnt
                self._ql.emu_start(begin=begin, end=0,
                                   timeout=timeout)
            else:  # run for count instructions
                self._ql.emu_start(begin=begin, end=0,
                                   count=count, timeout=timeout)
        else:  # run from beginning address to end address
            self._ql.emu_start(begin=begin, end=end, timeout=timeout)

        # Update the registers after the instruction is executed
        m = self._ql.arch.regs.register_mapping
        regs = {}
        for k in m:
            regs[k] = self._ql.arch.regs.read(k)
        self._regs = regs

        # Update the current state
        self._simple_disassembler(self.cur_addr)
        self.update_current_state()

    def _simple_disassembler(self, address: int) -> None:
        """
        Disassembles the instruction at the specified address.
        """
        # Disassemble the memory part to remap it to what instruction happened.
        insn = self.disasm(address, True)

        if insn is None:
            self._insn_info = self.disasm(address - self.arch_insn_size, True)
            self.update_current_state()
            print(hex(self.cur_addr - self.arch_insn_size)
                  + "[Inferior 1 exited normally]")
            self._running = False
            return
        self._insn_info = insn

    def _breakpoint_hit(self) -> bool:
        """
        Handles the breakpoint hit event.
        """
        state = self.stop()
        print("Breakpoint hit at line " + str(state.get('line_number'))
              + f" {{{self.cur_addr:#x}}}")
        # restore original instruction
        self._ql.mem.write(self.cur_addr, self._breakpoints[self.cur_addr])

    @staticmethod
    def parse_objdump_output(output: str) -> dict:
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
        if self._interrupt is not None:
            state['interrupt'] = self._interrupt
        else:
            state['interrupt'] = 'na'
        # get instruction information from param and read information to get
        # line number and info about instruction
        line_number = self.objdump.get(self.cur_addr)
        state['line_number'] = line_number

        insn_map = {}
        insn_map['memory'] = self._insn_info.address
        instruct = f'{self._insn_info.mnemonic:s} {self._insn_info.op_str:s}'
        insn_map['instruction'] = instruct
        state['insn'] = insn_map

        state['regs'] = self.get_registers

        self._current_state = state
        return state

    def read_mem(self, address: int, size: int):
        """
        read data from memory of qiling instance
        """

        return self._ql.mem.read(address, size)

    def disasm(self, address: int, detail: bool = False) -> Optional[CsInsn]:
        """
        helper function for disassembling
        """

        md = self._ql.arch.disassembler
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

    def _inter_read(self, _ql: Qiling, intno: Optional[int]):
        """
        interrupt reader prints interrupt number and sets interrupt number
        when qiling hooks to interrupt
        """
        if intno is not None:
            self._interrupt = intno
        if self.cur_addr in self._breakpoints and self.breakpoints_enabled:
            self._breakpoint_hit()
