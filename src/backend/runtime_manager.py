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


class RuntimeManager:
    """
    Manages the runtime execution of ARMv8 assembly code.
    """

    def __init__(self, assembly_file: str):
        self.assembly_file = assembly_file
        self.obj_file = None
        self.executable = None
        self.rootfs_loc = r"./rootfs/arm64_linux"

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

    def run(self) -> str:
        """
        Runs the executable and returns the output.
        """
        # If the executable is not created, link it.
        if self.executable is None:
            if self.obj_file is None:
                self.assemble()
            self.link()
        # logging is restricted to warnings, errors and critical entries

        ql = Qiling([self.executable],
                    self.rootfs_loc,
                    verbose=QL_VERBOSE.OFF)
        ql.run()

    def debug(self, debugger_server: 'debugger_server') -> None:
        """
        Starts a debugging session using the provided debugger_server.
        """
        pass


def main():
    '''dvsd'''
    manager = RuntimeManager("sampleWorkspace/helloWorld.s")
    manager.run()
    # print(output)
    
if __name__ == "__main__":
    main()