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
import shutil
import subprocess  # nosec
import os
import shlex
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling_debugger import QilingDebugger


class RuntimeManager:
    """
    Manages the runtime execution of ARMv8 assembly code.
    """

    def __init__(self, assembly_file: str, file_system: str = 'arm64_linux'):
        self.assembly_file = assembly_file
        self.obj_file = None
        self.executable = None
        # self.rootfs_loc = r"./rootfs/arm64_linux"
        self.rootfs_loc = os.path.join('.', 'rootfs', file_system)
        self.debugger = None

    def assemble(self) -> str:
        """
        Assembles the ARMv8 assembly code into a binary file.
        Returns the path to the binary file.

        .s file -> .o file
        """
        # command_path = '/usr/bin/aarch64-linux-gnu-as'
        command_path = self.get_command_path('assemble')
        safe_assembly_file = shlex.quote(self.assembly_file)

        # Replace file extension with .o. If windows use .obj
        if os.uname().sysname == 'Windows':
            extension = '.obj'
        else:
            extension = '.o'
        self.obj_file = os.path.splitext(self.assembly_file)[0] + extension
        # Construct the command as a list of arguments
        command = [command_path, safe_assembly_file,
                   '-g', '-o', self.obj_file]

        try:
            result = subprocess.run(  # nosec
                command, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, result.args,
                    output=result.stdout, stderr=result
                )
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Subprocess execution failed.") from e
        return self.obj_file

    def link(self) -> str:
        """
        Links the assembled code into an executable.
        Returns the path to the executable.

        .o file -> executable
        """
        # executable_path = '/usr/bin/aarch64-linux-gnu-ld'
        command_path = self.get_command_path(
            'link')

        if self.obj_file is None:
            assembled = self.check_dir(self.assembly_file)[0]
            if not assembled:
                self.assemble()

        safe_obj_file = shlex.quote(self.obj_file)
        self.executable = os.path.splitext(self.assembly_file)[0]
        command = [command_path, safe_obj_file, '-o', self.executable]

        try:
            result = subprocess.run(  # nosec
                command, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, result.args,
                    output=result.stdout, stderr=result
                )
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Subprocess execution failed.") from e

        return self.executable

    def run(self, verbosity: str = 'default'):
        """
        Runs the executable with the specified verbosity level.

        Args:
            verbosity (str): The verbosity level
            ('off', 'info', 'debug', 'trace').
        """
        self.verify_executable()

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
        self.verify_executable()

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
        self.debugger = QilingDebugger(ql, dump)
        return self.debugger

    def start_debugger(self):
        """
        Starts the debugger.
        """
        if self.debugger is not None:
            self.debugger.start(self.executable)
        else:
            self.debug()
            self.debugger.start(self.executable)

    def objdump(self) -> str:
        """
        Disassembles the executable file.
        Returns the disassembled code as a string.
        """
        # command_path = '/usr/bin/aarch64-linux-gnu-objdump'
        command_path = self.get_command_path(
            'objdump'
        )

        self.verify_executable()  # Ensure the executable file exists

        disassembly = subprocess.run([command_path,  # nosec
                                      '-d', '-l', self.executable],
                                     check=True, capture_output=True)
        return disassembly.stdout.decode()

    def verify_executable(self):
        """
        Verifies the existence of the executable file.

        Creates the executable file if it does not exist.
        """
        if self.executable is None:  # If the executable is not defined
            # Check if the directory contains the obj and executable files
            (assembled, linked) = self.check_dir(self.assembly_file)
            # If the executable file exists we only need to set the exe path
            if linked:
                self.executable = os.path.splitext(self.assembly_file)[0]
            else:  # If the executable file does not exist
                if not assembled:  # If the obj file does not exist
                    self.assemble()
                if self.obj_file is None:  # If the obj file is not defined
                    self.obj_file = os.path.splitext(
                        self.assembly_file
                    )[0] + '.o'
                self.link()  # Link the obj file to create the executable file

    @staticmethod
    def check_dir(path: str) -> tuple:
        """
        Checks if the provided path contains the obj file and executable
        corresponding to the given assembly source code file.

        Args:
            path (str): The directory path to check.
            e.g. 'sampleWorkspace/helloWorld.s'.

        Returns:
            tuple: A tuple containing two boolean values. The first boolean
                indicates whether an obj file is present, and the second
                boolean indicates whether an executable file is present.
        """
        base_name = os.path.splitext(path)[0]
        obj_file = base_name + '.o'
        exe_file = base_name

        obj_exists = os.path.isfile(obj_file)
        exe_exists = os.path.isfile(exe_file) and os.access(exe_file, os.X_OK)

        return obj_exists, exe_exists

    @staticmethod
    def get_command_path(mode: str) -> str:
        """
        Get the path of the specified GNU ARM toolchain command based on
        the current operating system and mode.

        Args:
            mode (str): The mode indicating the type of command. Should be
            one of 'assemble', 'link', or 'objdump'.

        Returns:
            str: The path to the command.

        Raises:
            ValueError: If the mode is unknown or the command is not found
            in the system's PATH.
        """
        # get os name
        os_name = os.uname().sysname

        if mode == 'assemble':
            if os_name == 'Linux' or os_name == 'Darwin':
                command = 'aarch64-linux-gnu-as'
            # windows
            elif os_name == 'Windows':
                command = 'aarch64-none-linux-gnu-as'
        elif mode == 'link':
            if os_name == 'Linux' or os_name == 'Darwin':
                command = 'aarch64-linux-gnu-ld'
            elif os_name == 'Windows':
                command = 'aarch64-none-linux-gnu-ld'
        elif mode == 'objdump':
            if os_name == 'Linux' or os_name == 'Darwin':
                command = 'aarch64-linux-gnu-objdump'
            elif os_name == 'Windows':
                command = 'aarch64-none-linux-gnu-objdump'
        else:
            raise ValueError(f"Unknown mode: {mode}")

        # check if the command is in the path
        path = shutil.which(command)
        if path is None:
            link = "https://developer.arm.com/downloads/-/\
            arm-gnu-toolchain-downloads"
            raise ValueError(
                f"'{command}' command not found.\n"
                "Please download and install the GNU ARM toolchain from:\n"
                f"{link}"
            )
        return path


def main():
    '''Temporary main function for testing purposes.'''
    manager = RuntimeManager("sampleWorkspace/helloWorld.s")
    debugger = manager.debug('off')
    debugger.start(manager.executable)  # line 15
    for _ in range(2):  # line 16 and 17
        debugger.step()
    debugger.set_breakpoint_line(24, None)
    debugger.cont()  # line 24
    debugger.step()  # line 25
    print(debugger.get_current_state.get('line_number'))
    debugger.restart(None)
    debugger.step()  # Program is not running
    debugger.start(manager.executable)  # line 15
    for _ in range(2):  # line 16 and 17
        debugger.step()
    debugger.set_breakpoint_line(19, None)
    debugger.cont()  # line 19
    print(debugger.get_current_state.get('line_number'))
    debugger.cont()  # line 24
    debugger.step()  # line 25
    print(debugger.get_current_state.get('line_number'))
    debugger.restart(None)
    debugger.cont()  # Program is not running
    debugger.start(manager.executable)  # line 15
    debugger.cont()  # line 19
    print(debugger.get_current_state.get('line_number'))
    debugger.toggle_breakpoints()
    debugger.cont()
    print(debugger.get_current_state.get('line_number'))
    debugger.step()
    debugger.step()
    print(debugger.get_current_state.get('line_number'))


if __name__ == "__main__":
    main()
