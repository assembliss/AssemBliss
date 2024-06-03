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
This module provides a RuntimeManager class for managing the runtime 
execution of ARMv8 assembly code.

The RuntimeManager class provides methods for assembling, linking, running, 
and debugging ARMv8 assembly code.
"""
import subprocess
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE

from qiling_debugger import QilingDebugger


class RuntimeManager:
    """
    Manages the runtime execution of ARMv8 assembly code.
    """
    @property
    def debugger(self) -> QilingDebugger:
        """
        Returns the debugger instance
        """
        return self._debugger

    def __init__(self, assembly_file: str):
        self.assembly_file = assembly_file
        self.obj_file = None
        self.executable = None
        self.rootfs_loc = r"./rootfs/arm64_linux"
        self._debugger = None

    def assemble(self) -> str:
        """
        Assembles the ARMv8 assembly code into a binary file.
        Returns the path to the binary file.
        """
        executable_path = '/usr/bin/aarch64-linux-gnu-as'
        # Replace file extension with .obj. Can be any extension.
        self.obj_file = os.path.splitext(self.assembly_file)[0] + '.obj'
        subprocess.run([executable_path, self.assembly_file,
                        '-g', '-o', self.obj_file], check=True)
        return self.obj_file

    def link(self) -> str:
        """
        Links the assembled code into an executable.
        Returns the path to the executable.
        """
        executable_path = '/usr/bin/aarch64-linux-gnu-ld'
        # Remove the .obj extension.
        self.executable = os.path.splitext(self.assembly_file)[0]
        subprocess.run([executable_path, self.obj_file,
                        '-o', self.executable], check=True)
        return self.executable

    def run(self, verbosity: str = 'default'):
        """
        Runs the executable with the specified verbosity level.

        Args:
            verbosity (str): The verbosity level ('off', 'info', 'debug', 'trace').
        """
        if self.executable is None:
            if self.obj_file is None:
                self.assemble()
            self.link()

        # Map verbosity levels to QL_VERBOSE levels
        if verbosity == 'off':
            verbose_level = QL_VERBOSE.OFF
        elif verbosity == 'default':
            verbose_level = QL_VERBOSE.DEFAULT
        elif verbosity == 'debug':
            verbose_level = QL_VERBOSE.DEBUG
        elif verbosity == 'trace':
            verbose_level = QL_VERBOSE.DUMP
        else:
            raise ValueError(f"Unknown verbosity level: {verbosity}")

        ql = Qiling([self.executable], rootfs=self.rootfs_loc,
                    verbose=verbose_level)
        ql.run()

    def debug(self, verbosity: str = "debug") -> QilingDebugger:
        """
        Starts a debugging session using the provided qiling_debugger.
        """
        if self.executable is None:  # TODO: add check for file in dir
            if self.obj_file is None:
                self.assemble()
            self.link()

        if verbosity == 'off':
            verbose_level = QL_VERBOSE.OFF
        elif verbosity == 'default':
            verbose_level = QL_VERBOSE.DEFAULT
        elif verbosity == 'debug':
            verbose_level = QL_VERBOSE.DEBUG
        elif verbosity == 'trace':
            verbose_level = QL_VERBOSE.DUMP
        else:
            raise ValueError(f"Unknown verbosity level: {verbosity}")

        ql = Qiling([self.executable], rootfs=self.rootfs_loc,
                    verbose=verbose_level)
        dump = self.objdump()
        self._debugger = QilingDebugger(ql, dump)

        self.debugger.start(self.executable)
        return self.debugger

    def objdump(self) -> str:
        """
        Disassembles the executable file.
        Returns the disassembled code as a string.
        """
        executable_path = '/usr/bin/aarch64-linux-gnu-objdump'

        if self.executable is None:  # TODO: add check for file in dir
            if self.obj_file is None:
                self.assemble()
            self.link()

        disassembly = subprocess.run([executable_path,
                                      '-d', '-l', self.executable],
                                     check=True, capture_output=True)
        return disassembly.stdout.decode()


def main():
    '''Temporary main function for testing purposes.'''
    debugger = RuntimeManager("sampleWorkspace/helloWorld.s").debug('off')
    for i in range(8):
        debugger.step()
        if debugger.current_state['interrupt'] == 2:
            print(debugger.current_state['interrupt'])
            print(debugger.current_state['line_number'])
if __name__ == "__main__":
    main()
